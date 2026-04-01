#include "dns.h"
#include "utils.h"
#include "csum.h"
#include "gets.h"
#include "ttl.h"
#include "csum.h"
#include "dns_filter.h"
#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __uint(key_size, sizeof(char[MAX_DNS_NAME_LENGTH]));
    __uint(map_flags, 0);
    __uint(value_size, sizeof(struct a_record));
 } cache_arecords SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, 4);
    __uint(value_size, 4);
    __uint(map_flags, 0);
} time_cache SEC(".maps");

#define EDNS0_OPT_SIZE      11
#define ETH_HDR_SIZE        14
#define IP_HDR_SIZE         20
#define UDP_HDR_SIZE        8
#define DNS_HDR_SIZE        12
#define MAX_DNS_NAME_LENGTH 56

#define MAX_DNS_QUERY_SIZE  (DNS_HDR_SIZE + MAX_DNS_NAME_LENGTH + 1 + 2 + 2 + EDNS0_OPT_SIZE)
#define MAX_PACKET_SIZE     (ETH_HDR_SIZE + IP_HDR_SIZE + UDP_HDR_SIZE + MAX_DNS_QUERY_SIZE)
SEC("xdp")
int dns_filter(struct xdp_md *ctx) {

    void *data_end = (void*) (long) ctx->data_end;
    void *data = (void*) (long) ctx->data;

     __u64 pkt_size = data_end - data;

    if (pkt_size > MAX_PACKET_SIZE)
        return XDP_PASS;

    __u64 offset_h = 0;

    switch (filter_dns(data, &offset_h, data_end))
    {
        case DROP:
            return XDP_DROP;
        case PASS:
        case FROM_DNS_PORT:
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
            break;
        default:
            return XDP_DROP;
            break;
    }
    
    dnsquery.id.port = get_source_port(data);

    uint8_t domain_size = 0;

    switch (get_domain(data, &offset_h, data_end, &dnsquery.query, &domain_size))
    {
        case DROP:
            return XDP_DROP;
        case PASS:
            return XDP_PASS;
        default:
            break;
    }

    volatile struct a_record *arecord;
    arecord = bpf_map_lookup_elem(&cache_arecords, dnsquery.query.name);

    if (arecord)
    {      
        __u32 key = 0;
        __u32 *now;

        now = bpf_map_lookup_elem(&time_cache, &key);
        // __u32 now = (__u32)(clock_gettime_ns() / 1000000000ULL);

        __u32 diff = 0;
        
        if (now)
            diff = get_ttl(arecord->timestamp, *now);

        if (diff >  MINIMUM_TTL)
        {
            __s16 newsize = (data + offset_h - data_end);

            __u8 status = RCODE_NXDOMAIN;

            if (arecord->ip != 0)
            {
                newsize += sizeof(struct dns_response);
                status = RCODE_NOERROR;
            }

            if (bpf_xdp_adjust_tail(ctx, (int) newsize) < 0)
            {    
                return XDP_DROP;
            }

            data = (void*) (long) ctx->data;
            data_end = (void*) (long) ctx->data_end;

            offset_h = 0;

            if (format_network_acess_layer(data, &offset_h, data_end) == DROP)
                 return XDP_DROP;
        
            if (swap_internet_layer(data, &offset_h, data_end) == DROP)
                 return XDP_DROP;

            if (swap_transport_layer(data, &offset_h, data_end) == DROP)
                 return XDP_DROP;

            if (create_dns_answer(data, &offset_h, data_end, arecord->ip, diff, status, domain_size) == DROP)
                 return XDP_DROP;

            return XDP_TX;
        }
    }

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
