#ifndef DNS_H
#define DNS_H

#include <stdint.h>
#include <string.h>
#include <linux/in.h>

// -----------------------------------------------------------------------------
// Packet Processing Results
// -----------------------------------------------------------------------------
#define DROP 0
#define PASS 1
#define ACCEPT 2
#define ACCEPT_NO_ANSWER 3
#define ACCEPT_JUST_POINTER 3
#define ACCEPT_ERROR 4

// -----------------------------------------------------------------------------
// Network Protocol Constants
// -----------------------------------------------------------------------------
#define MAX_UDP_SIZE 512
#define IPV4 0x0800
#define IP_FRAGMENTED_MASK 65343
#define UDP_PROTOCOL 0x11
#define UDP_NO_ERROR 0x0

// -----------------------------------------------------------------------------
// DNS Constants
// -----------------------------------------------------------------------------
#define MAX_DNS_PAYLOAD 500

#define DNS_PORT 53
#define TO_DNS_PORT 2
#define FROM_DNS_PORT 3

#define DNS_QUERY_TYPE 0
#define DNS_RESPONSE_TYPE 1

#define DNS_RA 1

#define DNS_QR_SHIFT 15
#define DNS_RA_SHIFT 7
#define DNS_RD_SHIFT 8

// -- DNS Record Types --
#define A_RECORD_TYPE 1
#define AAA_RECORD_TYPE 28
#define NS_RECORD_TYPE 2
#define CNAME_RECORD_TYPE 5
#define SOA_RECORD_TYPE 6 
#define OPT_TYPE 41
#define DS_TYPE 43

// -- DNS Record Classes --
#define DNS_CLASS_IN 1

// -- DNS Message Format --
#define DNS_POINTER_OFFSET 0xc00c
#define MAX_DNS_NAME_LENGTH 255
#define MAX_SUBDOMAIN_LENGTH 127
#define MAX_DNS_LABELS 127

// -- DNS Query/Response Handling --
#define QUERY_RETURN 2
#define RESPONSE_RETURN 3
#define QUERY_ADDITIONAL_RETURN 4
#define QUERY_NAMESERVERS_RETURN 5

#define ANSWER 1
#define ADDITIONAL 2
#define NAMESERVERS 3
#define NOTHING 0

// -----------------------------------------------------------------------------
// Cache and Query Management
// -----------------------------------------------------------------------------
#define MINIMUM_TTL 15
#define MAX_LABELS_CHECK 10

// -----------------------------------------------------------------------------
// eBPF Program Tail Call Indices
// -----------------------------------------------------------------------------
#define DNS_JUMP_QUERY_PROG 0
#define DNS_CREATE_NEW_QUERY_PROG 1
#define DNS_BACK_TO_LAST_QUERY 2
#define DNS_CHECK_SUBDOMAIN_PROG 3
#define DNS_ERROR_PROG 4
#define DNS_SEND_EVENT_PROG 5
#define DNS_UDP_CSUM_PROG 6
#define DNS_RESPONSE_PROG 7

// -----------------------------------------------------------------------------
// DNS Response Codes (RCODE)
// -----------------------------------------------------------------------------
#define RCODE_NOERROR 0
#define RCODE_SERVERFAIL 2
#define RCODE_NXDOMAIN 3


#ifndef memset
    #define memset(dest, chr, n) __builtin_memset((dest), (chr), (n))
#endif

#ifndef memcpy
    #define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#ifndef memmove
    #define memmove(dest, src, n) __builtin_memmove((dest), (src), (n))
#endif

/**
 * @brief Represents the header of a DNS message.
 */
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

/**
 * @brief Represents a DNS answer record.
 */
struct dns_response {
   uint16_t query_pointer;
   uint16_t record_type;
   uint16_t record_class;
   uint32_t ttl;
   uint16_t data_length;
   uint32_t ip;
} __attribute__((packed));

/**
 * @brief Represents an authoritative server record in a DNS response.
 */
struct dns_authoritative {
   uint16_t query_pointer;
   uint16_t record_type;
   uint16_t class;
   uint32_t ttl;
   uint16_t data_length;
} __attribute__((packed));

/**
 * @brief Represents a cached A record with its expiration timestamp.
 */
struct a_record {
    __u32 ip;
    __u64 timestamp;
};

/**
 * @brief Represents a DNS domain name.
 */
struct dns_domain {
    __u8 domain_size;
    char name[MAX_DNS_NAME_LENGTH];
};

/**
 * @brief Represents a hop in the recursive query process, tracking the query state.
 */
struct hop_query
{
    // Combined state field: Lower 8 bits track recursion depth.
    // 9th bit, when set, flags the next response's source IP to be cached
    // as a known authoritative nameserver.
    __u16 recursion_state;
    __u16 pointer;
    struct dns_domain query;
};

/**
 * @brief Represents a DNS query identifier (Transaction ID and port).
 */
struct id {
    __u16 id;
    __u16 port;
};

/**
 * @brief Represents a full DNS query, including its ID and the domain name.
 */
struct dns_query {
    struct id id;
    struct dns_domain query;
};

/**
 * @brief Represents a small, partial domain name for recursive queries.
 */
struct rec_query_domain {
    __u8 domain_size;
    char name[3];
};

/**
 * @brief Represents the key for a recursive query in the eBPF map.
 */
struct rec_query_key {
    struct id id;
    struct rec_query_domain query;
};

/**
 * @brief Stores information about the original client of a recursive query.
 */
struct query_owner {
    __be32 ip;
    __u8 rec;
    __u8 not_cache;
    __u8 curr_pointer;
};

/**
 * @brief Represents the current query being processed by a specific server.
 */
struct curr_query
{
    struct id id;
    __u32 ip;
};

/**
 * @brief Represents an event sent from the eBPF program to the userspace application.
 */
struct event {
    char domain[MAX_DNS_NAME_LENGTH];
    __u32 len;
    __u32 ips[4];
    __u16 id;
    __u16 port;
};

#endif
