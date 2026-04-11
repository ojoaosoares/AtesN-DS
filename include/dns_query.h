#ifndef DNS_QUERY_H
#define DNS_QUERY_H

#include <linux/types.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "dns.h"

static __always_inline __u8 get_domain_sw(void *data, __u64 *offset, void *data_end, struct dns_domain_sw *query)
{
    __u8 *content = (__u8 *)((__u8 *)data + *offset);
    *offset += sizeof(__u8);
    if ((void *)((__u8 *)data + *offset) > data_end)
        return DROP;

    if (*(content) == 0)
        return DROP;

    size_t size;
    for (size = 0; (size < MAX_DNS_NAME_LENGTH_SW && *(content + size) != 0); size++)
    {
        query->name[size] = *(char *)(content + size);
        if ((void *)((__u8 *)data + ++(*offset)) > data_end)
            return DROP;
    }
    query->domain_size = (__u8) size;

    content = (__u8 *)((__u8 *)data + *offset);
    *offset += (sizeof(__u8) * 4);
    if ((void *)((__u8 *)data + *offset) > data_end)
        return DROP;

    if (bpf_ntohs(*((__u16 *) content)) ^ A_RECORD_TYPE)
        return PASS;

    content += 2;
    if (bpf_ntohs(*((__u16 *) content)) ^ DNS_CLASS_IN)
        return PASS;
    
    return ACCEPT;
}

static __always_inline __u8 get_domain_hw(void *data, __u64 *offset, void *data_end, struct dns_domain_hw *query, __u8 *domain_size)
{
    __u8 *content = (__u8 *)((__u8 *)data + *offset);
    *offset += sizeof(__u8);
    if ((void *)((__u8 *)data + *offset) > data_end)
        return DROP;

    if (*(content) == 0)
        return DROP;

    __builtin_memset(query->name, 0, MAX_DNS_NAME_LENGTH_HW);
    size_t size;
    #pragma unroll
    for (size = 0; (size < MAX_DNS_NAME_LENGTH_HW && *(content + size) != 0); size++)
    {
        query->name[size] = *(char *)(content + size);
        if ((void *)((__u8 *)data + ++(*offset)) > data_end)
            return DROP;
    }
    (*domain_size) = (__u8) size;

    content = (__u8 *)((__u8 *)data + *offset);
    *offset += (sizeof(__u8) * 4);
    if ((void *)((__u8 *)data + *offset) > data_end)
        return DROP;

    if (bpf_ntohs(*((__u16 *) content)) ^ A_RECORD_TYPE)
        return PASS;

    content += 2;
    if (bpf_ntohs(*((__u16 *) content)) ^ DNS_CLASS_IN)
        return PASS;
    
    return ACCEPT;
}

static __always_inline __u8 write_query(void *data, __u64 *offset, void *data_end, struct dns_domain_sw *query) {
    __u8 *content = (__u8 *)data + *offset;
    for (size_t i = 0; i < query->domain_size; i++)
    {
        if ((void *)((__u8 *)data + ++*(offset)) > data_end)
            return DROP;
        if (i < MAX_DNS_NAME_LENGTH_SW)
            *(content + i) = query->name[i];
    }

    content = (__u8 *)data + *offset;
    if ((void *)((__u8 *)data + ++*(offset)) > data_end)
            return DROP;

    *(content) = (__u8) 0;
    content++;
    (*offset) += 4;
    if ((void *)((__u8 *)data + *(offset)) > data_end)
        return DROP;

    (* (__u16 *) content) = bpf_htons(A_RECORD_TYPE);
    content += 2;
    (* (__u16 *) content) = bpf_htons(DNS_CLASS_IN);
    return ACCEPT;
}

static __always_inline __u8 create_dns_query(void *data, __u64 *offset, void *data_end) {
    struct dns_header *header = (struct dns_header *)((__u8 *)data + *offset);
    *offset += sizeof(struct dns_header);
    if ((void *)((__u8 *)data + *offset) > data_end)
        return DROP;

    header->questions = bpf_htons(1);
    header->answer_count = bpf_htons(0);
    header->name_servers = bpf_htons(0);
    header->additional_records = bpf_htons(0);
    header->flags = bpf_htons(0x0100);
    return ACCEPT;
}

#endif
