#ifndef DNS_H
#define DNS_H

#include <stdint.h>
#include <stddef.h>
#include <linux/types.h>
#include <linux/in.h>

// -----------------------------------------------------------------------------
// Compatibility & Helpers
// -----------------------------------------------------------------------------
#ifndef BPF_MAP_TYPE_RINGBUF
#define BPF_MAP_TYPE_RINGBUF 27
#endif

#ifndef memset
#define memset(dest, chr, n) __builtin_memset((dest), (chr), (n))
#endif

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#ifndef memmove
#define memmove(dest, src, n) __builtin_memmove((dest), (src), (n))
#endif

// -----------------------------------------------------------------------------
// Packet Processing Results
// -----------------------------------------------------------------------------
enum packet_action {
    DROP = 0,
    PASS = 1,
    ACCEPT = 2,
    ACCEPT_NO_ANSWER = 3,
    ACCEPT_JUST_POINTER = 3,
    ACCEPT_ERROR = 4
};

// -----------------------------------------------------------------------------
// Network Protocol Constants
// -----------------------------------------------------------------------------
#define MAX_UDP_SIZE        512
#define IPV4                0x0800
#define IP_FRAGMENTED_MASK  65343
#define UDP_PROTOCOL        0x11
#define UDP_NO_ERROR        0x0

// -----------------------------------------------------------------------------
// DNS Message Constants
// -----------------------------------------------------------------------------
#define DNS_PORT            53
#define MAX_DNS_PAYLOAD     500
#define DNS_POINTER_OFFSET  0xc00c

// DNS Processing Status (Return codes internal to logic)
#define TO_DNS_PORT              2
#define FROM_DNS_PORT            3
#define QUERY_RETURN             2
#define RESPONSE_RETURN          3
#define QUERY_ADDITIONAL_RETURN  4
#define QUERY_NAMESERVERS_RETURN 5

// DNS Types & Classes
#define A_RECORD_TYPE       1
#define NS_RECORD_TYPE      2
#define CNAME_RECORD_TYPE   5
#define SOA_RECORD_TYPE     6
#define AAA_RECORD_TYPE     28
#define OPT_TYPE            41
#define DS_TYPE             43
#define DNS_CLASS_IN        1

// DNS Header Flags & Fields
#define DNS_QUERY_TYPE      0
#define DNS_RESPONSE_TYPE   1
#define DNS_QR_SHIFT        15
#define DNS_RA_SHIFT        7
#define DNS_RD_SHIFT        8

// DNS Response Codes (RCODE)
#define RCODE_NOERROR       0
#define RCODE_SERVERFAIL    2
#define RCODE_NXDOMAIN      3

// DNS Length Limits
#define MAX_DNS_NAME_LENGTH_HW 56
#define MAX_DNS_NAME_LENGTH_SW 256
#define MAX_SUBDOMAIN_LENGTH   127
#define MAX_DNS_LABELS         127

// -----------------------------------------------------------------------------
// Cache & Recursive Logic Configuration
// -----------------------------------------------------------------------------
#define MINIMUM_TTL         15
#define MAX_LABELS_CHECK    10
#define RECURSION_LIMIT     16

// -----------------------------------------------------------------------------
// eBPF Program Tail Call Indices
// -----------------------------------------------------------------------------
enum tail_prog_index {
    DNS_JUMP_QUERY_PROG       = 0,
    DNS_CREATE_NEW_QUERY_PROG = 1,
    DNS_BACK_TO_LAST_QUERY    = 2,
    DNS_CHECK_SUBDOMAIN_PROG  = 3,
    DNS_ERROR_PROG            = 4,
    DNS_ERROR_PREVENTION_PROG = 5,
    DNS_RESPONSE_PROG         = 6,
    DNS_PRE_FETCH_PROG        = 7
};

// -----------------------------------------------------------------------------
// DNS Protocol Structures
// -----------------------------------------------------------------------------

/**
 * @brief DNS Fixed Header
 */
struct dns_header {
    __be16 id;
    __be16 flags;
    __be16 questions;
    __be16 answer_count;
    __be16 name_servers;
    __be16 additional_records;
} __attribute__((packed));

/**
 * @brief DNS Resource Record (Answer/Authority/Additional)
 */
struct dns_response {
    __be16 query_pointer;
    __be16 record_type;
    __be16 record_class;
    __be32 ttl;
    __be16 data_length;
    __be32 ip;
} __attribute__((packed));

/**
 * @brief DNS Authoritative Record Header (no data field)
 */
struct dns_authoritative {
    __be16 query_pointer;
    __be16 record_type;
    __be16 class;
    __be32 ttl;
    __be16 data_length;
} __attribute__((packed));

// -----------------------------------------------------------------------------
// eBPF Map Value & Logic Structures
// -----------------------------------------------------------------------------

/**
 * @brief Cached DNS record (Software version)
 */
struct a_record_sw {
    __u64 timestamp;
    __u32 ip;
    __u8  prefetch;
} __attribute__((packed));

/**
 * @brief Cached DNS record (Hardware version)
 */
struct a_record_hw {
    __u32 timestamp;
    __u32 ip;
} __attribute__((aligned(8)));

/**
 * @brief Domain name container (Software version)
 */
struct dns_domain_sw {
    __u8 domain_size;
    char name[MAX_DNS_NAME_LENGTH_SW * 2];
};

/**
 * @brief Domain name container (Hardware version)
 */
struct dns_domain_hw {
    char name[MAX_DNS_NAME_LENGTH_HW];
} __attribute__((aligned(8)));

/**
 * @brief DNS query identification
 */
struct id {
    __u16 id;
    __u16 port;
};

/**
 * @brief Full DNS query context
 */
struct dns_query {
    struct id id;
    struct dns_domain_sw query;
};

/**
 * @brief Recursive query hop state
 */
struct hop_query {
    __u16 recursion_state;
    __u16 pointer;
    struct dns_domain_sw query;
};

/**
 * @brief Partial domain for map keys
 */
struct rec_query_domain {
    __u8 domain_size;
    char name[3];
};

/**
 * @brief Map key for recursive queries
 */
struct rec_query_key {
    struct id id;
    struct rec_query_domain query;
};

/**
 * @brief Recursive query ownership and state
 */
struct query_owner {
    __be32 ip;
    __u8 rec;
    __u8 not_cache;
    __u8 curr_pointer;
};

/**
 * @brief Context for current in-flight query
 */
struct curr_query {
    struct id id;
    __u32 ip;
};

// -----------------------------------------------------------------------------
// Userspace Event Structures
// -----------------------------------------------------------------------------

/**
 * @brief Event for error prevention (authoritative IP pre-resolution)
 */
struct event_error_p {
    char domain[MAX_DNS_NAME_LENGTH_SW];
    __u32 len;
    __u32 ips[4];
    __u16 id;
    __u16 port;
};

/**
 * @brief Event for domain pre-fetching
 */
struct event_prefetch {
    char domain[MAX_DNS_NAME_LENGTH_SW];
    __u32 ip;
    __u16 id;
    __u16 port;
};

#endif
