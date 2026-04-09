#ifndef DNS_ANSWER_H
#define DNS_ANSWER_H

#include <linux/types.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "dns.h"

static __always_inline __u8 create_no_dns_answer(void *data, __u64 *offset, void *data_end, __u8 status)
{
     struct dns_header *header = (struct dns_header *)((__u8 *)data + *offset);
     *offset += sizeof(struct dns_header);
     if ((void *)((__u8 *)data + *offset) > data_end)
         return DROP;

     __u16 flags = 0x8180 + status;
     header->name_servers = bpf_htons(0);
     header->additional_records = bpf_htons(0);
     header->answer_count = bpf_htons(0);    
     header->flags = bpf_htons(flags);
     return ACCEPT;
}

static __always_inline __u8 create_dns_answer(void *data, __u64 *offset, void *data_end, __u32 ip, __u32 ttl, __u8 status, __u16 domain_size) {
     struct dns_header *header = (struct dns_header *)((__u8 *)data + *offset);
     *offset += sizeof(struct dns_header);
     if ((void *)((__u8 *)data + *offset) > data_end)
         return DROP;

     __u16 flags = 0x8180 + status;
     header->name_servers = bpf_htons(0);
     header->additional_records = bpf_htons(0);

     if (ip == 0) {
         flags = 0x8180 + 3;
         header->flags = bpf_htons(flags);
         header->answer_count = bpf_htons(0);
         return ACCEPT;
     }

     header->flags = bpf_htons(flags);
     header->answer_count = bpf_htons(1);
     *offset += domain_size + 5;
    
     struct dns_response *response = (struct dns_response *)((__u8 *)data + *offset);
     *offset += sizeof(struct dns_response);
     if ((void *)((__u8 *)data + *offset) > data_end)
         return DROP;

     response->query_pointer = bpf_htons(DNS_POINTER_OFFSET);
     response->record_class = bpf_htons(DNS_CLASS_IN);
     response->record_type = bpf_htons(A_RECORD_TYPE);
     response->ttl = bpf_htonl(ttl);
     response->data_length = bpf_htons(sizeof(ip));
     response->ip = ip;
     return ACCEPT;
}

static __always_inline __u8 get_dns_answer_sw(void *data, __u64 *offset, void *data_end, struct a_record_sw *record) {
    struct dns_header *header = (struct dns_header *)((__u8 *)data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr));
    struct dns_response *response = (struct dns_response *)((__u8 *)data + *offset);

    if ((bpf_ntohs(header->flags) & 0x000F) == 2)
        return ACCEPT_NO_ANSWER;
    if ((bpf_ntohs(header->flags) & 0x000F) != 0 && (bpf_ntohs(header->flags) & 0x000F) != 3)
        return ACCEPT_ERROR;

    if (bpf_ntohs(header->answer_count)) {
        *offset += sizeof(struct dns_response);
        if ((void *)((__u8 *)data + *offset) > data_end)
            return DROP;

        if(bpf_ntohs(response->record_type) == CNAME_RECORD_TYPE && bpf_ntohs(header->answer_count) > 1) {
            if (bpf_ntohs(response->data_length) > MAX_DNS_NAME_LENGTH_SW)
                return ACCEPT_NO_ANSWER;
            *offset += bpf_ntohs(response->data_length) - 4;
            response = (struct dns_response *)((__u8 *)data + *offset);
            *offset += sizeof(struct dns_response);
            if ((void *)((__u8 *)data + *offset) > data_end)
                return DROP;
        }

        if (bpf_ntohs(response->record_type) != A_RECORD_TYPE)
            return ACCEPT_NO_ANSWER;
        if (bpf_ntohs(response->record_class) != DNS_CLASS_IN)
            return ACCEPT_NO_ANSWER;

        record->ip = response->ip;
        record->timestamp = (__u32)((bpf_ktime_get_ns() / 1000000000) + bpf_ntohl(response->ttl));
        return ACCEPT;
    } else if (bpf_ntohs(header->name_servers)) {
        *offset += sizeof(struct dns_response);
        if ((void *)((__u8 *)data + *offset) > data_end)
            return DROP;
        if (bpf_ntohs(response->record_type) != SOA_RECORD_TYPE)
            return ACCEPT_NO_ANSWER;
        if (bpf_ntohs(response->record_class) != DNS_CLASS_IN)
            return ACCEPT_NO_ANSWER;

        record->ip = 0;
        record->timestamp = (bpf_ktime_get_ns() / 1000000000) + bpf_ntohl(response->ttl);
        return ACCEPT;  
    }
    return ACCEPT_NO_ANSWER;
}

static __always_inline __u8 get_dns_answer_hw(void *data, __u64 *offset, void *data_end, struct a_record_hw *record, __u32 now) {
     struct dns_header *header = (struct dns_header *)((__u8 *)data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr));
     struct dns_response *response = (struct dns_response *)((__u8 *)data + *offset);

     if ((bpf_ntohs(header->flags) & 0x000F) == 2)
         return ACCEPT_NO_ANSWER;
     if ((bpf_ntohs(header->flags) & 0x000F) != 0 && (bpf_ntohs(header->flags) & 0x000F) != 3)
         return ACCEPT_ERROR;

     if (bpf_ntohs(header->answer_count)) {
         *offset += sizeof(struct dns_response);
         if ((void *)((__u8 *)data + *offset) > data_end)
             return DROP;
         if (bpf_ntohs(response->record_type) != A_RECORD_TYPE)
             return ACCEPT_NO_ANSWER;
         if (bpf_ntohs(response->record_class) != DNS_CLASS_IN)
             return ACCEPT_NO_ANSWER;

         record->ip = response->ip;
         record->timestamp = now + bpf_ntohl(response->ttl);
         return ACCEPT;
     }
     return ACCEPT_NO_ANSWER;
 }

#endif
