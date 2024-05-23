#ifndef DNS
#define DNS

#include <stdint.h>

#define IPV4 0x0800
#define IP_FRAGMENTET 65343
#define UDP_PROTOCOL 0x11
#define DNS_PORT 0x35

#define DNS_QUERY_TYPE 1
#define MAX_DOMAIN 255
#define END_DOMAIN 0

struct dns_header
{
    uint16_t id;
    
    union
    {
        uint16_t query_or_response    :1;
        uint16_t kind_of_query        :4;
        uint16_t authoritative_answer :1;
        uint16_t truncation           :1;
        uint16_t recursion_desired    :1;
        uint16_t recursion_available  :1;
        uint16_t future_use           :3;
        uint16_t response_code        :4;
    };
    
    uint16_t questions;
    uint16_t answer_count;
    uint16_t name_servers;
    uint16_t additional_records;
};

#endif