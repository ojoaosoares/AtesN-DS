#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "dns.h"

/* -------------------------------------------------------------------------
 * Maps (Strictly matching AtesN-DS schema from src/dns.c and include/dns.h)
 * ------------------------------------------------------------------------- */

/* In-flight query tracking map strictly matching AtesN-DS */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __uint(key_size, sizeof(struct rec_query_key));
    __uint(value_size, sizeof(struct query_owner));
} recursive_queries SEC(".maps");

/* Hardware cache synchronization ring buffer map */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, HW_SYNC_RINGBUF_SIZE);
} hw_sync_ringbuf SEC(".maps");

/* Per-CPU scratchpad to avoid BPF stack overflow */
struct listener_scratch {
    char qname[MAX_DNS_NAME_LENGTH_HW];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct listener_scratch));
} tmp_scratch_buf SEC(".maps");

/* Telemetry counters */
struct listener_stats_val {
    __u64 egress_queries_tracked;
    __u64 ingress_responses_matched;
    __u64 sync_events_submitted;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct listener_stats_val));
} listener_stats_map SEC(".maps");

static __always_inline void update_stat(int field) {
    __u32 key = 0;
    struct listener_stats_val *s = bpf_map_lookup_elem(&listener_stats_map, &key);
    if (!s) return;
    if (field == 0) s->egress_queries_tracked++;
    else if (field == 1) s->ingress_responses_matched++;
    else if (field == 2) s->sync_events_submitted++;
}

/* Identical helper to notify_hw_cache in src/dns.c (lines 35-43) */
static __always_inline void notify_hw_cache(const char *name, __u8 domain_size, __be32 ip, __u64 timestamp) {
    /* Only submit event if domain fits in hardware cache (<= 56 bytes) */
    if (domain_size > MAX_DNS_NAME_LENGTH_HW)
        return;
    struct hw_cache_sync_event *evt = bpf_ringbuf_reserve(&hw_sync_ringbuf, sizeof(*evt), 0);
    if (!evt)
        return;
    __builtin_memcpy(evt->name, name, MAX_DNS_NAME_LENGTH_HW);
    evt->ip = ip;
    evt->timestamp = (__u32)timestamp;
    bpf_ringbuf_submit(evt, 0);
    update_stat(2);
}

#define DNS_PORT            53
#define DNS_FLAG_QR         0x8000
#define DNS_RCODE_MASK      0x000F

/* -------------------------------------------------------------------------
 * TC Egress Hook:
 * Only intercepts outgoing queries dispatched by Unbound (dport == 53).
 * Records rec_query_key -> query_owner in recursive_queries.
 * TC does NOT touch responses.
 * ------------------------------------------------------------------------- */
SEC("tc")
int tc_dns_egress(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = (struct ethhdr *)data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    if (ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK;

    __u32 ip_hlen = ip->ihl * 4;
    if (ip_hlen < sizeof(struct iphdr))
        return TC_ACT_OK;

    struct udphdr *udp = (struct udphdr *)((__u8 *)ip + ip_hlen);
    if ((void *)(udp + 1) > data_end)
        return TC_ACT_OK;

    /* TC only captures outgoing queries to upstream servers */
    if (udp->dest != bpf_htons(DNS_PORT))
        return TC_ACT_OK;

    struct dns_header *dns = (struct dns_header *)(udp + 1);
    if ((void *)(dns + 1) > data_end)
        return TC_ACT_OK;

    /* Must be a standard query: QR == 0, OPCODE == 0, exactly 1 question */
    __u16 flags = bpf_ntohs(dns->flags);
    if ((flags & DNS_FLAG_QR) != 0 || (flags & 0x7800) != 0)
        return TC_ACT_OK;

    if (bpf_ntohs(dns->questions) != 1)
        return TC_ACT_OK;

    __u8 *content = (__u8 *)(dns + 1);
    if ((void *)(content + 1) > data_end || *content == 0)
        return TC_ACT_OK;

    struct rec_query_key key = {0};
    key.id.id = dns->id;
    key.id.port = udp->source;

    size_t qname_len = 0;
    int found_null = 0;

    #pragma unroll
    for (int i = 0; i < MAX_DNS_NAME_LENGTH_HW; i++) {
        if ((void *)(content + i + 1) > data_end)
            return TC_ACT_OK;
        __u8 c = content[i];
        if (i < sizeof(key.query.name)) {
            key.query.name[i] = (char)c;
        }
        if (c == 0) {
            qname_len = i;
            found_null = 1;
            break;
        }
    }

    if (!found_null || qname_len == 0)
        return TC_ACT_OK;

    __u8 *qtail = content + qname_len + 1;
    if ((void *)(qtail + 4) > data_end)
        return TC_ACT_OK;

    __be16 qtype = *(__be16 *)qtail;
    __be16 qclass = *(__be16 *)(qtail + 2);
    if (qtype != bpf_htons(A_RECORD_TYPE) || qclass != bpf_htons(DNS_CLASS_IN))
        return TC_ACT_OK;

    key.query.domain_size = (__u8)qname_len;

    struct query_owner owner = {
        .ip = ip->saddr,
        .rec = 0,
        .not_cache = 0,
        .curr_pointer = 0
    };

    bpf_map_update_elem(&recursive_queries, &key, &owner, BPF_ANY);
    update_stat(0);

    return TC_ACT_OK;
}

/* -------------------------------------------------------------------------
 * XDP Ingress Hook:
 * Intercepts incoming authoritative responses (sport == 53).
 * Matches against in-flight queries in recursive_queries using rec_query_key.
 * Parses the validated A answer and submits to SmartNIC via notify_hw_cache.
 * ------------------------------------------------------------------------- */
SEC("xdp")
int xdp_dns_ingress(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = (struct ethhdr *)data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    __u32 ip_hlen = ip->ihl * 4;
    if (ip_hlen < sizeof(struct iphdr))
        return XDP_PASS;

    struct udphdr *udp = (struct udphdr *)((__u8 *)ip + ip_hlen);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    /* XDP only captures incoming responses from upstream servers */
    if (udp->source != bpf_htons(DNS_PORT))
        return XDP_PASS;

    struct dns_header *dns = (struct dns_header *)(udp + 1);
    if ((void *)(dns + 1) > data_end)
        return XDP_PASS;

    __u16 flags = bpf_ntohs(dns->flags);
    /* Must be response: QR == 1, RCODE == NOERROR, answer_count >= 1 */
    if (!(flags & DNS_FLAG_QR) || (flags & DNS_RCODE_MASK) != 0)
        return XDP_PASS;

    if (bpf_ntohs(dns->answer_count) == 0 || bpf_ntohs(dns->questions) != 1)
        return XDP_PASS;

    __u8 *content = (__u8 *)(dns + 1);
    if ((void *)(content + 1) > data_end || *content == 0)
        return XDP_PASS;

    __u32 zero = 0;
    struct listener_scratch *scratch = bpf_map_lookup_elem(&tmp_scratch_buf, &zero);
    if (!scratch)
        return XDP_PASS;

    struct rec_query_key key = {0};
    key.id.id = dns->id;
    key.id.port = udp->dest;

    size_t qname_len = 0;
    int found_null = 0;

    #pragma unroll
    for (int i = 0; i < MAX_DNS_NAME_LENGTH_HW; i++) {
        scratch->qname[i] = 0;
    }

    #pragma unroll
    for (int i = 0; i < MAX_DNS_NAME_LENGTH_HW; i++) {
        if ((void *)(content + i + 1) > data_end)
            return XDP_PASS;
        __u8 c = content[i];
        scratch->qname[i] = (char)c;
        if (i < sizeof(key.query.name)) {
            key.query.name[i] = (char)c;
        }
        if (c == 0) {
            qname_len = i;
            found_null = 1;
            break;
        }
    }

    if (!found_null || qname_len == 0)
        return XDP_PASS;

    key.query.domain_size = (__u8)qname_len;

    struct query_owner *owner = bpf_map_lookup_elem(&recursive_queries, &key);
    if (!owner)
        return XDP_PASS;

    update_stat(1);

    /* Jump directly to Answer section using qname_len */
    size_t ans_offset = DNS_QUESTION_OFFSET + qname_len + 1 + 4;
    if ((void *)((__u8 *)data + ans_offset + sizeof(struct dns_response)) > data_end) {
        bpf_map_delete_elem(&recursive_queries, &key);
        return XDP_PASS;
    }

    struct dns_response *ans = (struct dns_response *)((__u8 *)data + ans_offset);
    if ((void *)(ans + 1) > data_end) {
        bpf_map_delete_elem(&recursive_queries, &key);
        return XDP_PASS;
    }

    if (ans->record_type == bpf_htons(A_RECORD_TYPE) &&
        ans->record_class == bpf_htons(DNS_CLASS_IN) &&
        ans->data_length == bpf_htons(4)) {

        __u32 ans_ttl = bpf_ntohl(ans->ttl);
        if (ans_ttl >= MINIMUM_TTL) {
            __u64 exp_timestamp = (bpf_ktime_get_ns() / 1000000000ULL) + ans_ttl;
            notify_hw_cache(scratch->qname, (__u8)qname_len, ans->ip, exp_timestamp);
        }
    }

    bpf_map_delete_elem(&recursive_queries, &key);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
