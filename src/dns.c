#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_vlan.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "dns.h"
#include "csum.h"
#include "gets.h"
#include "ttl.h"
#include "net_format.h"
#include "dns_headers.h"
#include "dns_query.h"
#include "dns_answer.h"
#include "dns_filter.h"

// -----------------------------------------------------------------------------
// Maps
// -----------------------------------------------------------------------------

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} ringbuf_send_packet SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY); 
    __uint(max_entries, 8);                
    __uint(key_size, sizeof(__u32)); 
    __uint(value_size, sizeof(__u32));       
} tail_programs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __uint(key_size, sizeof(struct rec_query_key));
    __uint(value_size, sizeof(struct query_owner));
} recursive_queries SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 655368*7);
    __uint(key_size, sizeof(struct rec_query_key));
    __uint(value_size, sizeof(struct hop_query));
} new_queries SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __uint(key_size, sizeof(char[MAX_DNS_NAME_LENGTH_SW]));
    __uint(value_size, sizeof(struct a_record_sw));
} cache_arecords SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 655368);
    __uint(key_size, sizeof(char[MAX_SUBDOMAIN_LENGTH]));
    __uint(value_size, sizeof(struct a_record_sw));
} cache_nsrecords SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct dns_query);
} tmp_key_buf SEC(".maps");

// Include recursive logic AFTER maps so it can access them
#include "dns_owner.h"
#include "dns_authoritative.h"
#include "dns_redirect.h"

// -----------------------------------------------------------------------------
// Globals (Initialized to avoid SHN_COMMON issues)
// -----------------------------------------------------------------------------

__u32 recursive_server_ip = 0;
__u32 serverip = 0;
unsigned char gateway_mac[6] = {0,0,0,0,0,0};

// -----------------------------------------------------------------------------
// XDP Programs
// -----------------------------------------------------------------------------

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
        case FROM_DNS_PORT:
            bpf_tail_call(ctx, &tail_programs, DNS_RESPONSE_PROG);
            return XDP_DROP;
        default:
            break;
    }

    struct dns_query dnsquery;

    __u8 query_response = is_dns_query_or_response(data, &offset_h, data_end, &dnsquery.id.id);

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
    }
    
    dnsquery.id.port = get_source_port(data);

    switch (get_domain_sw(data, &offset_h, data_end, &dnsquery.query))
    {
        case DROP:
            return XDP_DROP;
        case PASS:
            return XDP_PASS;
        default:
            break;
    }

    struct a_record_sw *arecord = bpf_map_lookup_elem(&cache_arecords, dnsquery.query.name);

    if (arecord)
    {   
        __u64 diff = get_ttl_sw(arecord->timestamp);

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

            if (format_network_access_layer_sw(data, &offset_h, data_end, gateway_mac) == DROP)
                return XDP_DROP;
        
            if (swap_internet_layer_sw(data, &offset_h, data_end) == DROP)
                return XDP_DROP;

            if (swap_transport_layer(data, &offset_h, data_end) == DROP)
                return XDP_DROP;

            if (create_dns_answer(data, &offset_h, data_end, arecord->ip, (uint32_t)diff, status, dnsquery.query.domain_size) == DROP)
                return XDP_DROP;

            if (diff - 3 <= MINIMUM_TTL && !arecord->prefetch)
            {
                arecord->prefetch = 1;

                struct curr_query curr = {
                    .id.id = dnsquery.id.id,
                    .id.port = get_dest_port(data),
                    .ip = get_dest_ip(data),
                };

                if (bpf_map_update_elem(&curr_queries, &curr, &dnsquery, BPF_ANY) >= 0)
                {
                    bpf_tail_call(ctx, &tail_programs, DNS_PRE_FETCH_PROG);
                    return XDP_DROP;
                }
            }

            return XDP_TX;
        }
        else {
            bpf_map_delete_elem(&cache_arecords, dnsquery.query.name);
        }
    }

    __u32 ip = recursive_server_ip;
    __u8 pointer = dnsquery.query.domain_size;

    if (find_owner_server(&dnsquery.query, &ip, &pointer))
        return XDP_PASS;
    
    struct query_owner owner = {
        .ip = get_source_ip(data),
        .rec = 0,
        .not_cache = 0,
        .curr_pointer = pointer
    };

    if(bpf_map_update_elem(&recursive_queries, (struct rec_query_key *) &dnsquery, &owner, BPF_ANY) < 0)
    {
        return XDP_PASS;
    }

    offset_h = 0;

    if (redirect_packet_keep(data, &offset_h, data_end, ip, serverip, gateway_mac) == DROP)
        return XDP_DROP;

    if (create_dns_query(data, &offset_h, data_end) == DROP)
        return XDP_DROP;

    return XDP_TX;
}


SEC("xdp") 
int dns_response(struct xdp_md *ctx)
{
    void *data = (void*) (long) ctx->data;
    void *data_end = (void*) (long) ctx->data_end;
    
    __u64 offset_h = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

    struct dns_query dnsquery;

    __u8 query_response = is_dns_query_or_response(data, &offset_h, data_end, &dnsquery.id.id);

    switch (query_response)
    {
        case DROP:
            return XDP_DROP;
        case PASS:
            return XDP_PASS;
        case QUERY_RETURN:
            break;
        default:
            break;
    }

    struct curr_query curr = {
        .id.id = dnsquery.id.id,
        .id.port = get_dest_port(data),
        .ip = get_source_ip(data),
    };

    dnsquery.id.port = curr.id.port;

    switch (get_domain_sw(data, &offset_h, data_end, &dnsquery.query))
    {
        case DROP:
            return XDP_DROP;
        case PASS:
            return XDP_PASS;
        default:
            break;
    }

    __u8 recursion_limit = 0, aprove = 0, ignore = 0, pointer = dnsquery.query.domain_size;

    struct query_owner *powner = NULL; struct hop_query *lastdomain = NULL;

    powner = bpf_map_lookup_elem(&recursive_queries, (struct rec_query_key *) &dnsquery);

    if (powner)
    {
        powner->rec++;

        if (powner->rec >= 16)
            recursion_limit = 1;

        if (!powner->ip)
            ignore = 1;

        if (powner->not_cache)
        {
            powner->not_cache = 0;
            aprove = 1;
            pointer = powner->curr_pointer;
        }
    }
    else 
    {
        lastdomain = bpf_map_lookup_elem(&new_queries, (struct rec_query_key *) &dnsquery);

        if (lastdomain)
        {
            __u8 rec = (uint8_t)++lastdomain->recursion_state;

            if (rec >= 16)
                recursion_limit = 1;

            if (lastdomain->recursion_state & (1 << 8)) 
            {
                lastdomain->recursion_state &= ~(1 << 8);
                aprove = 1;
                pointer = (uint8_t)(lastdomain->pointer >> 8);
            }
        }
        else
        {
            return XDP_PASS;
        }
    }

    if (aprove)
    {
        if ((dnsquery.query.domain_size - pointer <= MAX_SUBDOMAIN_LENGTH) && (pointer + MAX_SUBDOMAIN_LENGTH <= MAX_DNS_NAME_LENGTH_SW) && (pointer < MAX_DNS_NAME_LENGTH_SW))
        {
            struct a_record_sw *record_aprove = bpf_map_lookup_elem(&cache_nsrecords, (struct rec_query_key *) &dnsquery.query.name[pointer]);

            if (record_aprove)
            {
                record_aprove->ip = curr.ip;    
            }
        }
    }

    if (recursion_limit && query_response != RESPONSE_RETURN)
    {    
        if (hide_in_dest_ip(data, data_end, RCODE_SERVERFAIL) == DROP)
            return XDP_DROP;

        bpf_tail_call(ctx, &tail_programs, DNS_ERROR_PROG);
        return XDP_DROP;
    }

    if (query_response == RESPONSE_RETURN)
    {
        if (powner)
        {
            bpf_map_delete_elem(&recursive_queries, &dnsquery);

            offset_h = 0;

            if (redirect_packet_keep(data, &offset_h, data_end, powner->ip, serverip, gateway_mac) == DROP)
                return XDP_DROP;

            if (set_dns_header(data, &offset_h, data_end) == DROP)
                return XDP_DROP;
            
            offset_h += dnsquery.query.domain_size + 5;
            
            struct a_record_sw cache_record;
            cache_record.ip = 0;
            cache_record.timestamp = 0;
            cache_record.prefetch = 0;

            if (get_dns_answer_sw(data, &offset_h, data_end, &cache_record) == DROP)
                return XDP_DROP;

            if (cache_record.timestamp)
            {
                bpf_map_update_elem(&cache_arecords, dnsquery.query.name, &cache_record, BPF_ANY);
            }

            return XDP_TX;
        }
        else if (lastdomain) 
        {
            if (bpf_map_update_elem(&curr_queries, &curr, &dnsquery, BPF_ANY) < 0)
            {
                return XDP_PASS;
            }
            
            bpf_tail_call(ctx, &tail_programs, DNS_BACK_TO_LAST_QUERY);
            return XDP_DROP;
        }
        else return XDP_PASS;        
    }
    
    struct a_record_sw *record = NULL;

    if (powner && powner->ip)
    {
        record = bpf_map_lookup_elem(&cache_arecords, dnsquery.query.name);

        if (record)
        {   
            __u64 diff = get_ttl_sw(record->timestamp);

            if (diff >  MINIMUM_TTL)
            {
                bpf_map_delete_elem(&recursive_queries, &dnsquery);

                __s16 newsize = (data + offset_h - data_end);
                __u8 status = RCODE_NXDOMAIN;

                if (record->ip != 0)
                {
                    newsize += sizeof(struct dns_response); status = RCODE_NOERROR;
                }

                if (bpf_xdp_adjust_tail(ctx, (int) newsize) < 0)
                {
                    return XDP_DROP;
                }

                data = (void*) (long) ctx->data;
                data_end = (void*) (long) ctx->data_end;

                offset_h = 0;

                if (redirect_packet_keep(data, &offset_h, data_end, powner->ip, serverip, gateway_mac) == DROP)
                    return XDP_DROP;

                if (create_dns_answer(data, &offset_h, data_end, record->ip, (uint32_t)diff, status, dnsquery.query.domain_size) == DROP)
                    return XDP_DROP;

                return XDP_TX;
            }
            else
                bpf_map_delete_elem(&cache_arecords, dnsquery.query.name);
        }
    
        record = bpf_map_lookup_elem(&cache_nsrecords, (struct rec_query_key *) dnsquery.query.name);

        if (record && record->ip && record->ip != curr.ip)
        {   
            __u64 diff = get_ttl_sw(record->timestamp);

            if (diff >  MINIMUM_TTL)
            {
                if (powner)
                    powner->curr_pointer = 0;
                else if (lastdomain)
                    lastdomain->pointer &= 0x00FF;
                
                __s16 newsize = (data + offset_h - data_end);

                if (bpf_xdp_adjust_tail(ctx, (int) newsize) < 0)
                {
                    return XDP_DROP;
                }

                data = (void*) (long) ctx->data;
                data_end = (void*) (long) ctx->data_end;

                offset_h = 0;

                if (redirect_packet_swap(data, &offset_h, data_end, record->ip, serverip, gateway_mac) == DROP)
                    return XDP_DROP;

                if (create_dns_query(data, &offset_h, data_end) == DROP)
                    return XDP_DROP;

                return XDP_TX;
            }
            else
                bpf_map_delete_elem(&cache_nsrecords, dnsquery.query.name);
        }
    }

    if (query_response != RESPONSE_RETURN)
    {
        __u8 *content = (__u8 *)data + offset_h;

        if ((void *)((__u8 *)data + offset_h + 1) <= data_end)
        {
            if (*content == 0)
            {
                if (bpf_map_update_elem(&curr_queries, &curr, &dnsquery, BPF_ANY) < 0)
                {
                    return XDP_PASS;
                }

                if (hide_in_dest_ip(data, data_end, RCODE_SERVERFAIL) == DROP)
                    return XDP_DROP;

                bpf_tail_call(ctx, &tail_programs, DNS_ERROR_PROG);
                return XDP_DROP;
            }
        }      
    }

    if (query_response == QUERY_ADDITIONAL_RETURN)
    {
        __u8 pointer;

        switch (get_pointer(data, &offset_h, data_end, &pointer))
        {
            case DROP:
                return XDP_DROP;
            default:
                break;
        }

        if (hide_in_dest_ip(data, data_end, (uint32_t)pointer) == DROP)
            return XDP_DROP;

        if (bpf_map_update_elem(&curr_queries, &curr, &dnsquery, BPF_ANY) < 0)
        {
            return XDP_PASS;
        }

        if (powner)
        {
            powner->not_cache = 1;
            powner->curr_pointer = pointer;
        }
        else if (lastdomain)
        {
            lastdomain->recursion_state |= (1 << 8);
            lastdomain->pointer &= 0x00FF;
            lastdomain->pointer |= (uint16_t)(pointer << 8);
        }

        bpf_tail_call(ctx, &tail_programs, DNS_JUMP_QUERY_PROG);
        return XDP_DROP;
    }
    else if (query_response == QUERY_NAMESERVERS_RETURN)
    {
        __u8 pointer;

        switch (get_pointer(data, &offset_h, data_end, &pointer))
        {
            case DROP:
                return XDP_DROP;
            default:
                break;
        }

        if (powner)
        {
            if (hide_in_dest_ip(data, data_end, (uint32_t)powner->rec) == DROP)
                return XDP_DROP;    

            powner->curr_pointer = pointer;
        }
        else if (lastdomain)
        {
            if (hide_in_dest_ip(data, data_end, (uint32_t)lastdomain->recursion_state) == DROP)
                return XDP_DROP;

            lastdomain->pointer &= 0x00FF;
            lastdomain->pointer |= (uint16_t)(pointer << 8);
        }

        if (bpf_map_update_elem(&curr_queries, &curr, &dnsquery, BPF_ANY) < 0)
        {
            return XDP_PASS;
        }

        bpf_tail_call(ctx, &tail_programs, DNS_CHECK_SUBDOMAIN_PROG);
        return XDP_DROP;
    }

    return XDP_PASS;
}


SEC("xdp")
int dns_jump_query(struct xdp_md *ctx) {

    void *data = (void*) (long) ctx->data;
    void *data_end = (void*) (long) ctx->data_end;
    
    __u64 offset_h = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header);

    if (data + offset_h > data_end)
        return XDP_DROP;

    __u8 pointer = (uint8_t)get_dest_ip(data);
    hide_in_dest_ip(data, data_end, serverip);

    struct curr_query curr = {
        .id.id = get_query_id(data),
        .id.port = get_dest_port(data),
        .ip = get_source_ip(data)
    };

    struct dns_query *query = bpf_map_lookup_elem(&curr_queries, &curr);

    if (query)
    {
        if (query->query.domain_size >= MAX_DNS_NAME_LENGTH_SW)
            return XDP_DROP;

        offset_h += query->query.domain_size + 5;

        if (data + offset_h > data_end)
            return XDP_DROP;

        struct a_record_sw record;
        __u8 *remainder;
        
        switch (get_additional(data, &offset_h, data_end, &record, query->query.domain_size, &remainder))
        {
            case DROP:
                return XDP_DROP;
            case ACCEPT_NO_ANSWER:
                if (hide_in_dest_ip(data, data_end, RCODE_SERVERFAIL) == DROP)
                    return XDP_DROP;
                bpf_tail_call(ctx, &tail_programs, DNS_ERROR_PROG);
                return XDP_DROP;
            default:
                break;
        }
         
        __u16 remainder_off = (uint16_t)((long) ((void*) remainder) - (long) data);

        hide_in_source_port(data, bpf_htons(remainder_off)); 
        hide_in_dest_ip(data, data_end, record.ip);

        if ((query->query.domain_size - pointer <= MAX_SUBDOMAIN_LENGTH) && (pointer + MAX_SUBDOMAIN_LENGTH <= MAX_DNS_NAME_LENGTH_SW))
        {
            record.ip = 0;
            if (bpf_map_update_elem(&cache_nsrecords, &query->query.name[pointer], &record, BPF_ANY) < 0)
            {
                return XDP_PASS;
            }
        }

        bpf_tail_call(ctx, &tail_programs, DNS_ERROR_PREVENTION_PROG);
    }

    return XDP_DROP;
}

SEC("xdp")
int dns_check_subdomain(struct xdp_md *ctx) {

    void *data = (void*) (long) ctx->data;
    void *data_end = (void*) (long) ctx->data_end;
    
    __u64 offset_h = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header);

    if (data + offset_h > data_end)
        return XDP_DROP;

    __u8 deep = (uint8_t)get_dest_ip(data);
    hide_in_dest_ip(data, data_end, serverip);

    struct curr_query curr = {
        .id.id = get_query_id(data),
        .id.port = get_dest_port(data),
        .ip = get_source_ip(data)
    };

    struct dns_query *query = bpf_map_lookup_elem(&curr_queries, &curr);

    if (query) {

        __u8 pointer = 0, off = 0;

        if (query->query.domain_size > MAX_DNS_NAME_LENGTH_SW)
            return XDP_DROP;

        offset_h += query->query.domain_size + 5;

        if (data + offset_h > data_end)
            return XDP_DROP;

        struct dns_domain_sw subdomain;

        struct a_record_sw *nsrecord = NULL;

        switch (get_authoritative_pointer(data, &offset_h, data_end, &pointer, &off, &query->query, &subdomain))
        {
            case DROP:
                return XDP_DROP;   
            case ACCEPT:
                if (subdomain.domain_size <= MAX_SUBDOMAIN_LENGTH)
                    nsrecord = bpf_map_lookup_elem(&cache_nsrecords, subdomain.name);

                break;
            case ACCEPT_JUST_POINTER:
                if ((query->query.domain_size - pointer <= MAX_SUBDOMAIN_LENGTH) && (pointer + MAX_SUBDOMAIN_LENGTH <= MAX_DNS_NAME_LENGTH_SW) && (pointer < MAX_DNS_NAME_LENGTH_SW))
                    nsrecord = bpf_map_lookup_elem(&cache_nsrecords, query->query.name);            

            default:        
                break;
        }

        if (nsrecord && nsrecord->ip && nsrecord->ip != curr.ip)
        {
            __u64 diff = get_ttl_sw(nsrecord->timestamp);

            if (diff >  MINIMUM_TTL)
            {
                bpf_map_delete_elem(&curr_queries, &curr);

                __s16 newsize = (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header) + query->query.domain_size + 5 - data_end);

                if (bpf_xdp_adjust_tail(ctx, (int) newsize) < 0)
                {
                    return XDP_DROP;
                }

                data = (void*) (long) ctx->data;
                data_end = (void*) (long) ctx->data_end;

                offset_h = 0;

                if (format_network_access_layer_sw(data, &offset_h, data_end, gateway_mac) == DROP)
                    return XDP_DROP;
                
                if (return_to_network(data, &offset_h, data_end, nsrecord->ip, serverip) == DROP)
                    return XDP_DROP;

                if (swap_transport_layer(data, &offset_h, data_end) == DROP)
                    return XDP_DROP;

                if (create_dns_query(data, &offset_h, data_end) == DROP)
                    return XDP_DROP;

                return XDP_TX;
            }
            
            else
                bpf_map_delete_elem(&cache_nsrecords, subdomain.name);
        }

        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end)
            return XDP_DROP;

        if (hide_in_dest_ip(data, data_end, (uint32_t)(deep << 8 | pointer)) == DROP)
            return XDP_DROP;
        
        hide_in_source_port(data, bpf_htons(off));

        bpf_tail_call(ctx, &tail_programs, DNS_CREATE_NEW_QUERY_PROG);
        
        return XDP_DROP;
    }

    return XDP_PASS;
}

SEC("xdp")
int dns_create_new_query(struct xdp_md *ctx) {

    void *data = (void*) (long) ctx->data;
    void *data_end = (void*) (long) ctx->data_end;
    
    __u64 offset_h = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header);

    if (data + offset_h > data_end)
        return XDP_DROP;

    __u16 off = get_source_port(data); hide_in_source_port(data, bpf_htons(DNS_PORT));

    if (off > MAX_DNS_NAME_LENGTH_SW)
        return XDP_DROP;

    struct curr_query curr = {
        .id.id = get_query_id(data),
        .id.port = get_dest_port(data),
        .ip = get_source_ip(data)
    };
    
    struct dns_query *query = bpf_map_lookup_elem(&curr_queries, &curr);

    if (query) {

        struct dns_query dnsquery; 
        
        dnsquery.id.port = curr.id.port;
        dnsquery.id.id = curr.id.id;

        switch(get_authoritative(data, &offset_h, data_end, &dnsquery.query, &query->query, off))
        {
            case DROP:
                return XDP_DROP;
            case ACCEPT_NO_ANSWER:

                offset_h = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header) + query->query.domain_size + 5 + off - 2;

                struct a_record_sw cache_record;

                switch (get_dns_answer_sw(data, &offset_h, data_end, &cache_record))
                {
                    case DROP:
                        return XDP_DROP;

                    case ACCEPT_ERROR:
                    case ACCEPT_NO_ANSWER:

                        if (hide_in_dest_ip(data, data_end, RCODE_SERVERFAIL) == DROP)
                            return XDP_DROP;

                        bpf_tail_call(ctx, &tail_programs, DNS_ERROR_PROG);

                        return XDP_DROP;

                        break;
                    default:

                        bpf_map_update_elem(&cache_arecords, query->query.name, &cache_record, BPF_ANY);

                        if (hide_in_dest_ip(data, data_end, RCODE_NXDOMAIN) == DROP)
                            return XDP_DROP;

                        bpf_tail_call(ctx, &tail_programs, DNS_ERROR_PROG);
                        
                        return XDP_DROP;

                        break;
                }
                
                return XDP_DROP;                
            default:
                break;
        }

        bpf_map_delete_elem(&curr_queries, &curr);

        __u32 ip = recursive_server_ip; __u8 pointer;

        find_owner_server(&dnsquery.query, &ip, &pointer);
        
        __u32 value = get_dest_ip(data);
        hide_in_dest_ip(data, data_end, serverip);

        dnsquery.id.id += 1;

        modify_id(data, dnsquery.id.id); query->id.id = (uint16_t)((value >> 8) & 0xFF);

        query->id.port = (uint16_t)(((pointer & 0xFF) << 8) | (value & 0xFF));

	    if (bpf_map_update_elem(&new_queries, (struct rec_query_key *) &dnsquery, (struct hop_query *) query, BPF_ANY) < 0)
        {
            return XDP_DROP;
        }

        __s16 newsize = (__s16) ((data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header) +  dnsquery.query.domain_size + 5) - data_end);

        if (bpf_xdp_adjust_tail(ctx, (int) newsize) < 0)
        {
            return XDP_DROP;
        }

        data = (void*) (long) ctx->data;
        data_end = (void*) (long) ctx->data_end;

        offset_h = 0;

        if (redirect_packet_swap(data, &offset_h, data_end, ip, serverip, gateway_mac) == DROP)
            return XDP_DROP;

        if (create_dns_query(data, &offset_h, data_end) == DROP)
            return XDP_DROP;
        
        return XDP_TX;
    }

    return XDP_PASS;
}

SEC("xdp")
int dns_back_to_last_query(struct xdp_md *ctx) {

    void *data = (void*) (long) ctx->data;
    void *data_end = (void*) (long) ctx->data_end;
    
    __u64 offset_h = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header);

    if (data + offset_h > data_end)
        return XDP_DROP;

    struct curr_query curr = {
        .id.id = get_query_id(data),
        .id.port = get_dest_port(data),
        .ip = get_source_ip(data)
    };

    struct dns_query *query = bpf_map_lookup_elem(&curr_queries, &curr);

    if (query) {

        offset_h += query->query.domain_size + 5;

        if (data + offset_h > data_end)
            return XDP_DROP;

        struct hop_query *lastdomain = bpf_map_lookup_elem(&new_queries, query);

        if (lastdomain && lastdomain->query.domain_size <= MAX_DNS_NAME_LENGTH_SW)
        {
            __u32 ip = get_dest_ip(data);
            hide_in_dest_ip(data, data_end, serverip);

            __s16 newsize = (__s16) ((data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header)) - data_end) + lastdomain->query.domain_size + 5;

            if (ip == serverip)
            {
                struct a_record_sw cache_record;
                cache_record.ip = 0;
                cache_record.timestamp = 0;

                if (get_dns_answer_sw(data, &offset_h, data_end, &cache_record) == DROP)
                    return XDP_DROP;
            
                if (cache_record.timestamp)
                {
                    bpf_map_update_elem(&cache_arecords, query->query.name, &cache_record, BPF_ANY);
                }

                if (cache_record.ip == 0)
                {   
                    if (hide_in_dest_ip(data, data_end, RCODE_NXDOMAIN) == DROP)
                        return XDP_DROP;
                    
                    bpf_tail_call(ctx, &tail_programs, DNS_ERROR_PROG);

                    return XDP_PASS;
                }
                
                __u8 deep = (uint8_t)lastdomain->recursion_state, pointer = (uint8_t)lastdomain->pointer; ip = cache_record.ip;

                if (lastdomain->query.domain_size - pointer <= MAX_SUBDOMAIN_LENGTH && pointer + MAX_SUBDOMAIN_LENGTH <= MAX_DNS_NAME_LENGTH_SW)
                {
                    cache_record.ip = 0;

                    if (bpf_map_update_elem(&cache_nsrecords, &lastdomain->query.name[pointer], &cache_record, BPF_ANY) < 0)
                    {
                        return XDP_PASS;
                    }
                }

                lastdomain->recursion_state = curr.id.id - 1;
                lastdomain->pointer = curr.id.port;

                struct hop_query *last_of_last = bpf_map_lookup_elem(&new_queries, (struct rec_query_key *) lastdomain);

                if (last_of_last)
                {
                    last_of_last->recursion_state = deep;
                    last_of_last->recursion_state |= (1 << 8);
                }

                else
                {   
                    struct query_owner *powner = bpf_map_lookup_elem(&recursive_queries, (struct rec_query_key *) lastdomain);

                    if (powner)
                    {
                        powner->rec = deep;
                        powner->not_cache = 1;
                    }                    
                }
            }

            else
            {
                __u8 deep = (uint8_t)lastdomain->recursion_state;

                lastdomain->recursion_state = curr.id.id - 1;
                lastdomain->pointer = curr.id.port;

                struct hop_query *last_of_last = bpf_map_lookup_elem(&new_queries, (struct rec_query_key *) lastdomain);

                if (last_of_last)
                {
                    last_of_last->recursion_state = (uint16_t)deep;
                }

                else
                {
                    struct query_owner *powner = bpf_map_lookup_elem(&recursive_queries, (struct rec_query_key *) lastdomain);

                    if (powner)
                    {
                        powner->rec = deep;
                    }
                }
            }

                bpf_map_delete_elem(&curr_queries, &curr); bpf_map_delete_elem(&new_queries, query);

                if (bpf_xdp_adjust_tail(ctx, (int) newsize) < 0)
                {
                    return XDP_DROP;
                }

                data = (void*) (long) ctx->data;
                data_end = (void*) (long) ctx->data_end;

                offset_h = 0;      

                if (redirect_packet_swap(data, &offset_h, data_end, ip, serverip, gateway_mac) == DROP)
                    return XDP_DROP;

                if (create_dns_query(data, &offset_h, data_end) == DROP)
                    return XDP_DROP;

                modify_id(data, lastdomain->recursion_state);

                if (write_query(data, &offset_h, data_end, &lastdomain->query) == DROP)
                    return XDP_DROP;

                return XDP_TX;
        }

        bpf_map_delete_elem(&curr_queries, &curr);
    }

    return XDP_PASS;
}

SEC("xdp")
int dns_error(struct xdp_md *ctx) {

    void *data_end = (void*) (long) ctx->data_end;
    void *data = (void*) (long) ctx->data;

    __u64 offset_h = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header);

    if (data + offset_h > data_end)
        return XDP_DROP;

    __u8 status = (uint8_t)get_dest_ip(data);
    hide_in_dest_ip(data, data_end, serverip);

    struct curr_query curr = {
        .id.id = get_query_id(data),
        .id.port = get_dest_port(data),
        .ip = get_source_ip(data)
    };

    struct dns_query *query = bpf_map_lookup_elem(&curr_queries, &curr);

    if (query) {

        bpf_map_delete_elem(&curr_queries, &curr);

        struct hop_query *lastdomain = bpf_map_lookup_elem(&new_queries, (struct rec_query_key *) query);

        __u8 inter = 0;

        for (size_t i = 0; i < MAX_DNS_LABELS; i++)
        {
            if (lastdomain)
            {
                inter = 1;
                
                bpf_map_delete_elem(&new_queries, (struct rec_query_key *) query);

                __u16 id = query->id.id - 1, port = query->id.port;

                query = (struct dns_query *) lastdomain;
            
                query->id.id = id; query->id.port = port;
            }

            else
                break;

            lastdomain = bpf_map_lookup_elem(&new_queries, (struct rec_query_key *) query);
        }

        struct query_owner *powner = bpf_map_lookup_elem(&recursive_queries, (struct rec_query_key *) query);
        
        if (powner)
        {

            if (!powner->ip)
                return XDP_DROP;

            modify_id(data, query->id.id);

            bpf_map_delete_elem(&recursive_queries, query);

            if (query->query.domain_size > MAX_DNS_NAME_LENGTH_SW)
                return XDP_DROP;

            __s16 newsize = (__s16) ((data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header)) - data_end) + query->query.domain_size + 5;

            if (bpf_xdp_adjust_tail(ctx, (int) newsize) < 0)
            {
                return XDP_DROP;
            }

            data_end = (void*) (long) ctx->data_end;
            data = (void*) (long) ctx->data;

            offset_h = 0;

            if (redirect_packet_keep(data, &offset_h, data_end, powner->ip, serverip, gateway_mac) == DROP)
                return XDP_DROP;

            if (create_no_dns_answer(data, &offset_h, data_end, status) == DROP)
                return XDP_DROP;

            if (inter)
            {
                if (write_query(data, &offset_h, data_end, &query->query) == DROP)
                    return XDP_DROP;
            }

            return XDP_TX;
        }    
    }

    return XDP_DROP;
}

SEC("xdp")
int dns_error_prevention(struct xdp_md *ctx) {

    void *data_end = (void*) (long) ctx->data_end;
    void *data = (void*) (long) ctx->data;

    __u64 offset_h = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header);

    if (data + offset_h > data_end)
        return XDP_DROP;

    __u32 dest_ip = get_dest_ip(data);
    
    hide_in_dest_ip(data, data_end, serverip);

    __u16 remainder_offset = get_source_port(data);

    hide_in_source_port(data, bpf_htons(DNS_PORT));

    if (remainder_offset > MAX_UDP_SIZE)
        return XDP_DROP;

    struct curr_query curr = {
        .id.id = get_query_id(data),
        .id.port = get_dest_port(data),
        .ip = get_source_ip(data)
    };

    struct dns_query *query = bpf_map_lookup_elem(&curr_queries, &curr);

    if (query) {

        bpf_map_delete_elem(&curr_queries, &curr);

        __u8 *remainder = (__u8 *)data + remainder_offset;

        __u32 ips[4];
        
        int count = 0;

        for (int i = 0; i < 20; i++)
        {
            if ((void *)(remainder + 6) > data_end)
                break;

            else if ((*(remainder) & 0xC0) == 0xC0 && bpf_ntohs(*((__u16 *) (remainder + 2))) == A_RECORD_TYPE && bpf_ntohs(*((__u16 *) (remainder + 4))) == DNS_CLASS_IN)
            {        
                if ((void *)(remainder + 16) > data_end)
                    break;
                
                ips[count++] = *((__u32 *) (remainder + 12));

                remainder += (4 + 12);

                if (count == 4)
                    break;
            }

            else if ((*(remainder) & 0xC0) == 0xC0 && bpf_ntohs(*((__u16 *) (remainder + 2))) == AAA_RECORD_TYPE && bpf_ntohs(*((__u16 *) (remainder + 4))) == DNS_CLASS_IN)
            {
                remainder += (16 + 12);
            }
            
            else
                break;
        }


        if (count)
        {
            struct event_error_p *myevent = bpf_ringbuf_reserve(&ringbuf_send_packet, sizeof(struct event_error_p), 0);

            if (myevent) {

                __builtin_memcpy(myevent->domain, query->query.name, MAX_DNS_NAME_LENGTH_SW);

                myevent->id = get_query_id(data);
                myevent->port = get_dest_port(data);
                myevent->len = (uint32_t)count;
                
                for (size_t i = 0; i < 4; i++)
                    myevent->ips[i] = ips[i];

                bpf_ringbuf_submit(myevent, 0);
            }
        }

        

        __s16 newsize = (__s16) ((data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header) + query->query.domain_size + 5) - data_end);

        if (bpf_xdp_adjust_tail(ctx, (int) newsize) < 0)
        {
            return XDP_DROP;
        }

        data = (void*) (long) ctx->data;
        data_end = (void*) (long) ctx->data_end;

        offset_h = 0;

        if (redirect_packet_swap(data, &offset_h, data_end, dest_ip, serverip, gateway_mac) == DROP)
            return XDP_DROP;

        if (create_dns_query(data, &offset_h, data_end) == DROP)
            return XDP_DROP;
    }

    return XDP_TX;
}


SEC("xdp")
int dns_pre_fetch(struct xdp_md *ctx) {

    void *data_end = (void*) (long) ctx->data_end;
    void *data = (void*) (long) ctx->data;

    __u64 offset_h = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header);

    if (data + offset_h > data_end)
        return XDP_DROP;

    struct curr_query curr = {
        .id.id = get_query_id(data),
        .id.port = get_dest_port(data),
        .ip = get_dest_ip(data)
    };

    struct dns_query *query = bpf_map_lookup_elem(&curr_queries, &curr);

    if (query) {

        bpf_map_delete_elem(&curr_queries, &curr);


        struct event_prefetch *myevent = bpf_ringbuf_reserve(&ringbuf_send_packet, sizeof(struct event_prefetch), 0);

        if (myevent) {

            __builtin_memcpy(myevent->domain, query->query.name, MAX_DNS_NAME_LENGTH_SW);

            myevent->id = curr.id.id;
            myevent->port = curr.id.port;
            myevent->ip = serverip;

            bpf_ringbuf_submit(myevent, 0);

            __u32 rand32 = bpf_get_prandom_u32();
            __u16 rand16 = (__u16)(rand32 & 0xFFFF);

            query->id.id = rand16;

            struct query_owner owner = {
                .ip = 0,
                .rec = 0,
                .not_cache = 0,
                .curr_pointer = 0
            };

            bpf_map_update_elem(&recursive_queries, (struct rec_query_key *) query, &owner, BPF_ANY);
        }
    }

    return XDP_TX;
}


char _license[] SEC("license") = "GPL";
