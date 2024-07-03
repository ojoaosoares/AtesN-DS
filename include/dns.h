#ifndef DNS
#define DNS

#include <stdint.h>
#include <string.h>
#include "in.h"

#define IPV4 0x0800
#define IP_FRAGMENTET 65343
#define UDP_PROTOCOL 0x11
#define DNS_PORT 0x35

#define DNS_QUERY_TYPE 0
#define DNS_RESPONSE_TYPE 1

#define DNS_RA 1

#define DNS_QR_RIGHT_SHIFT 15
#define DNS_RA_RIGHT_SHIFT 7

#define A_RECORD_TYPE 1

#define INTERNT_CLASS 1

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
    uint16_t flags;

    // flags partition
    // qr                     1 bit
    // opcode                 4 bits
    // authoritative_answer   1 bit
    // truncation             1 bit
    // recursion_desired      1 bit
    // recursion_available    1 bit
    // future_use             3 bits
    // response_code          4 bits

    uint16_t questions;
    uint16_t answer_count;
    uint16_t name_servers;
    uint16_t additional_records;
};


struct dns_query {
    char name[MAX_DNS_NAME_LENGTH];
    uint16_t record_type;
    uint16_t class;
};

struct a_record {
    struct in_addr ip_addr;
    uint32_t ttl;
};

#endif