#include "dns.h"
#include "csum.h"
#include "gets.h"
#include "ttl.h"
#include "net_format.h"
#include "dns_headers.h"
#include "dns_query.h"
#include "dns_answer.h"
#include "dns_filter.h"
#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __uint(key_size, MAX_DNS_NAME_LENGTH_HW);
    __uint(map_flags, 0);
    __uint(value_size, sizeof(struct a_record_hw));
 } level_one_cache SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof( __u32));
    __uint(map_flags, 0);
} time_map SEC(".maps");

#define EDNS0_OPT_SIZE      11
#define ETH_HDR_SIZE        14
#define IP_HDR_SIZE         20
#define UDP_HDR_SIZE        8
#define DNS_HDR_SIZE        12
#define MAX_DNS_NAME_LENGTH 24
#define MAX_DNS_QUERY_SIZE  (DNS_HDR_SIZE + MAX_DNS_NAME_LENGTH + 1 + 2 + 2 + EDNS0_OPT_SIZE)
#define MAX_PACKET_SIZE     (ETH_HDR_SIZE + IP_HDR_SIZE + UDP_HDR_SIZE + MAX_DNS_QUERY_SIZE)

SEC("xdp")
int dns_filter(struct xdp_md *ctx) {

    void *data_end = (void*) (long) ctx->data_end;
    void *data = (void*) (long) ctx->data;

    __u64 offset_h = 0;

    switch (filter_dns(data, &offset_h, data_end))
    {
        case DROP:
            return XDP_DROP;
        case PASS:
            return XDP_PASS;
        default:
            break;
    }

    struct dns_query dnsquery = {0};

    __u64 query_response = is_dns_query_or_response(data, &offset_h, data_end, &dnsquery.id.id);

    switch (query_response)
    {
        case DROP:
            return XDP_DROP;
        case PASS:
            return XDP_PASS;
        case QUERY_RETURN:
        case RESPONSE_RETURN:
            break;
        default:
            return XDP_PASS;
            break;
    }
    
    dnsquery.id.port = get_source_port(data);

    uint8_t domain_size = 0;
    struct dns_domain_hw domain_hw = {0};

    switch (get_domain_hw(data, &offset_h, data_end, &domain_hw, &domain_size))
    {
        case DROP:
            return XDP_DROP;
        case PASS:
            return XDP_PASS;
        default:
            break;
    }

    __u32 *now = 0;
    __u32 key = 0;

    now = bpf_map_lookup_elem(&time_map, &key);

    if (!now)
        return XDP_PASS;

    if (RESPONSE_RETURN == query_response)
    {   
        offset_h = ETH_HDR_SIZE + IP_HDR_SIZE + UDP_HDR_SIZE + DNS_HDR_SIZE + domain_size + 5;

        if (data + offset_h > data_end)
            return XDP_DROP;
        
        struct a_record_hw cache_record = {0};
        cache_record.ip = 0;
        cache_record.timestamp = 0;

        __u32 now_value = *now;
        
        if (get_dns_answer_hw(data, &offset_h, data_end, &cache_record, now_value) == DROP)
            return XDP_DROP;

        if (cache_record.timestamp)
        {
            bpf_map_update_elem(&level_one_cache, domain_hw.name, &cache_record, BPF_ANY);
        }

        return XDP_PASS;
    }

    struct a_record_hw *arecord;
    arecord = bpf_map_lookup_elem(&level_one_cache, domain_hw.name);

    if (arecord)
    { 
	    __u32 now_value = *now;
        __u64 diff = 0;

        if (now_value < arecord->timestamp)
            diff = arecord->timestamp - now_value;
        
        if (diff < MINIMUM_TTL)
        {
            bpf_map_delete_elem(&level_one_cache, domain_hw.name);
            return XDP_PASS;
        }

        __s16 newsize = (data + offset_h - data_end);

        __u8 status = RCODE_NXDOMAIN;

        if (arecord->ip != 0)
        {
            newsize += sizeof(struct dns_response);
            status = RCODE_NOERROR;
        }

        if (bpf_xdp_adjust_tail(ctx, (int) newsize) < 0)
            return XDP_PASS;

        data = (void*) (long) ctx->data;
        data_end = (void*) (long) ctx->data_end;

        offset_h = 0;

        if (format_network_access_layer_hw(data, &offset_h, data_end) == DROP)
            return XDP_DROP;

        if (swap_internet_layer_hw(data, &offset_h, data_end) == DROP)
            return XDP_DROP;

        if (swap_transport_layer(data, &offset_h, data_end) == DROP)
            return XDP_DROP;

        if (create_dns_answer(data, &offset_h, data_end, arecord->ip, diff, status, domain_size) == DROP)
            return XDP_DROP;

        return XDP_TX;
    }

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
