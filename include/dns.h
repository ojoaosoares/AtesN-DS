#ifndef DNS
#define DNS

#include "bpf_helpers.h"

#define IPV4 0x0800
#define IP_FRAGMENTET 65343
#define UDP_PROTOCOL 0x11
#define DNS_PORT 0x35

struct dns_header
{
    __u16 id;
    
    union
    {
        __u16 query_or_response    :1;
        __u16 kind_of_query        :4;
        __u16 authoritative_answer :1;
        __u16 truncation           :1;
        __u16 recursion_desired    :1;
        __u16 recursion_available  :1;
        __u16 future_use           :3;
        __u16 response_code        :4;
    };
    
    __u16 questions;
    __u16 answer_count;
    __u16 name_servers;
    __u16 additional_records;
};


#endif