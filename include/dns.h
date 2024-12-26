#ifndef DNS
#define DNS

#include <stdint.h>
#include <string.h>
#include <linux/in.h>


#define DROP 0
#define PASS 1
#define ACCEPT 2

#define ACCEPT_NO_ANSWER 3

#define IPV4 0x0800
#define IP_FRAGMENTET 65343

#define UDP_PROTOCOL 0x11
#define UDP_NO_ERROR 0x0

#define DNS_PORT 0x35

#define TO_DNS_PORT 2
#define FROM_DNS_PORT 3

#define DNS_QUERY_TYPE 0
#define DNS_RESPONSE_TYPE 1

#define DNS_RA 1

#define DNS_QR_SHIFT 15
#define DNS_RA_SHIFT 7

#define A_RECORD_TYPE 1
#define NS_RECORD_TYPE 2

#define INTERNT_CLASS 1

#define DNS_POINTER_OFFSET 0xc00c

#define MAX_DNS_NAME_LENGTH 254
#define MAX_DNS_LABELS 127
#define END_DOMAIN 0x0


#define DNS_KEY_DOMAIN_LENGTH 350

#define QUERY_RETURN 2
#define RESPONSE_RETURN 3

#define NEW_QUERY 1
#define KEEP_QUERY 0


#define ANSWER 1
#define ADDITIONAL 2
#define NAMESERVERS 3
#define NOTHING 0

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
    __be16 id;
    __be16 flags;

    // flags partition
    // qr                     1 bit
    // opcode                 4 bits
    // authoritative_answer   1 bit
    // truncation             1 bit
    // recursion_desired      1 bit
    // recursion_available    1 bit
    // future_use             3 bits
    // response_code          4 bits

    __be16 questions;
    __be16 answer_count;
    __be16 name_servers;
    __be16 additional_records;
} __attribute__((packed));

struct dns_response {
   uint16_t query_pointer;
   uint16_t record_type;
   uint16_t class;
   uint32_t ttl;
   uint16_t data_length;
   uint32_t ip;
} __attribute__((packed));


struct a_record {
    struct in_addr ip_addr;
    uint32_t ttl;
};

// struct ns_record {
//     uint32_t ttl;
//     char name[MAX_DNS_NAME_LENGTH];
// };

struct hop_query_value {
    uint16_t record_type;
    char name[MAX_DNS_NAME_LENGTH];
    // uint16_t class;
};

struct dns_domain {
    __u16 record_type;
    char name[DNS_KEY_DOMAIN_LENGTH];
    // uint16_t class;
};

struct id {
    __u16 id;
    __u16 port;
};

struct dns_query {
    struct id id;
    struct dns_domain query;
};

struct rec_query_domain {
    __u16 record_type;
    char name[4];
};

struct rec_query_key {
    struct id id;
    struct rec_query_domain query;
};

struct query_owner {
    __u32 ip_address;
};

#endif
