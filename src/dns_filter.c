#include "dns.h"
#include "net_format.h"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2000000);
    __uint(key_size, MAX_DNS_NAME_LENGTH_HW);
    __uint(map_flags, 0);
    __uint(value_size, sizeof(struct a_record_hw));
} level_one_cache SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(map_flags, 0);
} time_map SEC(".maps");

SEC("xdp")
int dns_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    if ((void *)((__u8 *)data + DNS_MIN_QUERY_LEN) > data_end)
        return XDP_PASS;

    struct ethhdr *eth = (struct ethhdr *)data;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ipv4 = (struct iphdr *)((__u8 *)data + IPV4_OFFSET);
    if (ipv4->protocol != UDP_PROTOCOL)
        return XDP_PASS;
    if (ipv4->frag_off & IP_FRAGMENTED_MASK)
        return XDP_PASS;

    struct udphdr *udp = (struct udphdr *)((__u8 *)data + UDP_OFFSET);
    struct dns_header *dns = (struct dns_header *)((__u8 *)data + DNS_OFFSET);

    if (dns->questions != bpf_htons(1))
        return XDP_PASS;

    __u8 is_response = (dns->flags & bpf_htons(DNS_FLAG_QR)) != 0;

    if (!is_response) {
        if (udp->dest != bpf_htons(DNS_PORT) || dns->name_servers != 0)
            return XDP_PASS;
    } else {
        if (udp->source != bpf_htons(DNS_PORT))
            return XDP_PASS;
        __u16 rcode = bpf_ntohs(dns->flags) & DNS_RCODE_MASK;
        if (rcode != RCODE_NOERROR && rcode != RCODE_NXDOMAIN)
            return XDP_PASS;
        if (rcode == RCODE_NOERROR && dns->answer_count == 0)
            return XDP_PASS;
    }

    __u8 *content = (__u8 *)data + DNS_QUESTION_OFFSET;
    if (*content == 0)
        return XDP_DROP;

    struct dns_domain_hw domain_hw = {0};
    size_t size = MAX_DNS_NAME_LENGTH_HW;

    #pragma unroll
    for (size_t i = 0; i < MAX_DNS_NAME_LENGTH_HW; i++)
    {
        if ((void *)(content + i + 1) > data_end)
            return XDP_DROP;

        __u8 c = content[i];
        if (c == 0) {
            size = i;
            break;
        }
        domain_hw.name[i] = (char)c;
    }

    if ((void *)(content + size + DNS_QTAIL_LEN) > data_end)
        return XDP_DROP;

    if (size == MAX_DNS_NAME_LENGTH_HW && content[size] != 0)
        return XDP_PASS;

    __be16 *qtype  = (__be16 *)(content + size + 1);
    __be16 *qclass = (__be16 *)(content + size + 3);

    if (*qtype != bpf_htons(A_RECORD_TYPE) || *qclass != bpf_htons(DNS_CLASS_IN))
        return XDP_PASS;

    __u32 key = 0;
    __u32 *now = bpf_map_lookup_elem(&time_map, &key);
    if (!now)
        return XDP_PASS;
    __u32 now_value = *now;

    if (is_response)
    {
        struct dns_response *resp = (struct dns_response *)(content + size + DNS_QTAIL_LEN);
        struct a_record_hw cache_record = {0};

        __u16 rcode = bpf_ntohs(dns->flags) & DNS_RCODE_MASK;
        if (dns->answer_count != 0)
        {
            if ((void *)(resp + 1) > data_end)
                return XDP_DROP;

            if (resp->record_type == bpf_htons(A_RECORD_TYPE) && resp->record_class == bpf_htons(DNS_CLASS_IN))
            {
                cache_record.ip = resp->ip;
                cache_record.timestamp = now_value + bpf_ntohl(resp->ttl) + DNS_TTL_GRACE_SEC;
                bpf_map_update_elem(&level_one_cache, domain_hw.name, &cache_record, BPF_ANY);
            }
        }
        else if (rcode == RCODE_NXDOMAIN)
        {
            cache_record.ip = 0;
            cache_record.timestamp = now_value + DNS_TTL_GRACE_SEC;
            bpf_map_update_elem(&level_one_cache, domain_hw.name, &cache_record, BPF_ANY);
        }

        return XDP_PASS;
    }

    struct a_record_hw *arecord = bpf_map_lookup_elem(&level_one_cache, domain_hw.name);
    if (arecord)
    {
        __u32 diff = 0;
        if (now_value < arecord->timestamp)
            diff = arecord->timestamp - now_value;

        if (diff < MINIMUM_TTL)
        {
            bpf_map_delete_elem(&level_one_cache, domain_hw.name);
            return XDP_PASS;
        }

        __s16 newsize = ((__u8 *)data + DNS_QUESTION_OFFSET + size + DNS_QTAIL_LEN) - (__u8 *)data_end;
        __u8 status = RCODE_NXDOMAIN;

        if (arecord->ip != 0)
        {
            newsize += sizeof(struct dns_response);
            status = RCODE_NOERROR;
        }

        if (bpf_xdp_adjust_tail(ctx, (int)newsize) < 0)
            return XDP_PASS;

        data     = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;

        if (send_dns_response_hw(data, data_end, arecord->ip, diff, status, (__u8)size) == DROP)
            return XDP_DROP;

        return XDP_TX;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
