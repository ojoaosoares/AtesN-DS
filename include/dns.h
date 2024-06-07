#ifndef DNS
#define DNS

#include <stdint.h>
#include <string.h>

#define IPV4 0x0800
#define IP_FRAGMENTET 65343
#define UDP_PROTOCOL 0x11
#define DNS_PORT 0x35

#define DNS_QUERY_TYPE 1
#define MAX_DNS_NAME_LENGTH 256
#define MAX_DNS_LABEL_LENGTH 64
#define END_DOMAIN 0x0

#ifndef memset
    #define memset(dest, chr, n) __builtin_memset((dest), (chr), (n))
#endif

#ifndef memcpy
    #define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#ifndef memmove
    #define memmove(dest, src, n) __builtin_memmove((dest), (src), (n))
#endif


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


struct dns_query {
    uint16_t record_type;
    uint16_t class;
    __u8 name[MAX_DNS_NAME_LENGTH];
};


#endif