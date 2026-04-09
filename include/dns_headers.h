#ifndef DNS_HEADERS_H
#define DNS_HEADERS_H

#include <linux/types.h>
#include <bpf/bpf_endian.h>
#include "dns.h"

static __always_inline __u8 is_dns_query_or_response(void *data, __u64 *offset, void *data_end, __u16 *id)
{
    struct dns_header *header;
    header = (struct dns_header *)((__u8 *)data + *offset);
    
    *offset  += sizeof(struct dns_header);

    if ((void *)((__u8 *)data + *offset) > data_end)
    {      
        return DROP;
    }

    if (bpf_ntohs(header->questions) > 1)
    {
        return PASS;
    }

    *id = bpf_ntohs(header->id);

    if (bpf_ntohs(header->flags) & (1 << 15))
    {
        if (bpf_ntohs(header->answer_count) || (bpf_ntohs(header->flags) & 0x000F) ^ 0 || bpf_ntohs(header->flags) & (1 << 10))
            return RESPONSE_RETURN;

        if (bpf_ntohs(header->additional_records) && bpf_ntohs(header->name_servers))
            return QUERY_ADDITIONAL_RETURN;

        if (bpf_ntohs(header->name_servers))
            return QUERY_NAMESERVERS_RETURN;
    
        return RESPONSE_RETURN;
    }   

    if (bpf_ntohs(header->additional_records) && bpf_ntohs(header->name_servers))
        return QUERY_ADDITIONAL_RETURN;

    if (bpf_ntohs(header->name_servers))
        return QUERY_NAMESERVERS_RETURN;

    return QUERY_RETURN;
}

static __always_inline __u8 set_dns_header(void *data, __u64 *offset, void *data_end) {

     struct dns_header *header = (struct dns_header *)((__u8 *)data + *offset);

     *offset += sizeof(struct dns_header);

     if ((void *)((__u8 *)data + *offset) > data_end)
     {
         return DROP;
     }

     __u16 flags = bpf_ntohs(header->flags);
    
     flags |= 0x0080;
     flags &= ~0x0400; 

     header->flags = bpf_htons(flags);

     return ACCEPT;
}

static __always_inline void modify_id(void *data, __u16 id)
{
    struct dns_header *header = (struct dns_header *)((__u8 *)data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr));
    header->id = bpf_htons(id);
}

#endif
