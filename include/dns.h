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
#define DNS_RD_SHIFT 8

#define A_RECORD_TYPE 1
#define NS_RECORD_TYPE 2
#define CNAME_RECORD_TYPE 5
#define SOA_RECORD_TYPE 6 

#define INTERNT_CLASS 1

#define DNS_POINTER_OFFSET 0xc00c

#define MAX_DNS_NAME_LENGTH 254
#define MAX_DNS_LABELS 127
#define END_DOMAIN 0x0

#define QUERY_RETURN 2
#define RESPONSE_RETURN 3
#define QUERY_ADDITIONAL_RETURN 4
#define QUERY_NAMESERVERS_RETURN 5

#define ANSWER 1
#define ADDITIONAL 2
#define NAMESERVERS 3
#define NOTHING 0

#define MINIMUM_TTL 30

#define DNS_CHECK_CACHE_PROG 0
#define DNS_PROCESS_RESPONSE_PROG 1
#define DNS_JUMP_QUERY_PROG 2
#define DNS_CREATE_NEW_QUERY_PROG 3
#define DNS_BACK_TO_LAST_QUERY 4
#define DNS_SAVE_NS_CACHE_PROG 5
#define DNS_SELECT_SERVER_PROG 6
#define DNS_CHECK_SUBDOMAIN_PROG 6

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


struct dns_authoritative {
   uint16_t query_pointer;
   uint16_t record_type;
   uint16_t class;
   uint32_t ttl;
   uint16_t data_length;

} __attribute__((packed));


struct a_record {
    __u32 ip;
    __u32 ttl;
    __u64 timestamp;
    __u8 status;
};

// struct ns_record {
//     uint32_t ttl;
//     char name[MAX_DNS_NAME_LENGTH];
// };


struct dns_domain {
    __u16 record_type;
    __u8 domain_size;
    char name[MAX_DNS_NAME_LENGTH];
};

struct hop_query
{
    __u16 pointer;
    struct dns_domain query;
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
    __u8 domain_size;
    char name;
};

struct rec_query_key {
    struct id id;
    struct rec_query_domain query;
};

struct query_owner {
    unsigned char mac_address[6];
    __be32 ip_address;
};

struct curr_query
{
    struct id id;
    __u32 ip;
};

#endif
