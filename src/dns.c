#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_vlan.h> // Essential to verify the ip type
#include <linux/if_ether.h> // Essential for ethernet headers
#include <linux/if_packet.h>
#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "dns.h"

#define MIN(a, b) ((a) < (b) ? (a) : (b))

#define DOMAIN

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 1500000);
        __uint(key_size, sizeof(struct rec_query_key));
        __uint(value_size, sizeof(struct query_owner));
        __uint(pinning, LIBBPF_PIN_BY_NAME);

} recursive_queries SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 1500000);
        __uint(key_size, sizeof(struct rec_query_key));
        __uint(value_size, sizeof(struct hop_query_value));
        __uint(pinning, LIBBPF_PIN_BY_NAME);

} hop_queries SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_LRU_HASH);
        __uint(max_entries, 1500000);
        __uint(key_size, sizeof(char[MAX_DNS_NAME_LENGTH]));
        __uint(value_size, sizeof(struct a_record));

} cache_arecords SEC(".maps");

// struct {
//         __uint(type, BPF_MAP_TYPE_LRU_HASH);
//         __uint(max_entries, 1500000);
//         __uint(key_size, sizeof(char[DNS_KEY_DOMAIN_LENGTH - MAX_DNS_NAME_LENGTH]));
//         __uint(value_size, sizeof(struct ns_record));

// } cache_nsrecords SEC(".maps");

__be32 recursive_server_ip;

static __always_inline void print_ip(__u64 ip) {

    __u8 fourth = ip >> 24;
    __u8 third = (ip >> 16) & 0xFF;
    __u8 second = (ip >> 8) & 0xFF;
    __u8 first = ip & 0xFF;

    #ifdef DEBUG
        bpf_printk("IP: %d.%d.%d.%d", first, second, third, fourth);
    #endif

}

static inline __u16 calculate_ip_checksum(struct iphdr *ip)
{
    __u16 *pointer = (__u16*) ip;
    __u32 accumulator = 0;

    ip->check = 0;

    for (int i = 0; i < (sizeof(*ip) >> 1); i++)
        accumulator += *pointer++;
    
    return ~((accumulator & 0xffff) + (accumulator >> 16));
}

static __always_inline __u8 isIPV4(void *data, __u64 *offset, void *data_end)
{

    struct ethhdr *eth = data;

    *offset = sizeof(struct ethhdr);

    if (data + *offset > data_end)
    {
        #ifdef DEBUG
            bpf_printk("[DROP] No ethernet frame");
        #endif

        return DROP;
    }

    if(eth->h_proto ^ bpf_htons(IPV4))
    {
        #ifdef DEBUG
            bpf_printk("[PASS] Ethernet type isn't IPV4");
        #endif
        return PASS;
    }

    return ACCEPT;
}

static __always_inline __u8 isValidUDP(void *data, __u64 *offset, void *data_end, struct query_owner *owner)
{
    struct iphdr *ipv4;
    ipv4 = data + *offset;

    *offset += sizeof(struct iphdr);

    if (data + *offset > data_end)
    {
        #ifdef DEBUG
            bpf_printk("[DROP] No ip frame");
        #endif
        return DROP;
    }
    
    if (ipv4->frag_off & IP_FRAGMENTET)
    {
        #ifdef DEBUG
            bpf_printk("[PASS] Frame fragmented");
        #endif
        return PASS;
    }

    if (ipv4->protocol ^ UDP_PROTOCOL)
    {
        #ifdef DEBUG
            bpf_printk("[PASS] Ip protocol isn't UDP. Protocol: %d", ipv4->protocol);
        #endif

        return PASS;
    }

    owner->ip_address = ipv4->saddr;

    return ACCEPT;
}

static __always_inline __u8 isPort53(void *data, __u64 *offset, void *data_end, struct id *id)
{
    struct udphdr *udp;
    udp = data + *offset;
    *offset += sizeof(struct udphdr);

    if(data + *offset > data_end)
    {
        #ifdef DEBUG
            bpf_printk("[DROP] No UDP datagram");
        #endif
        return DROP;
    }

    id->port = udp->source;

    if (bpf_ntohs(udp->dest) == DNS_PORT)
        return TO_DNS_PORT;

    if (bpf_ntohs(udp->source) == DNS_PORT)
        return FROM_DNS_PORT;

    #ifdef DEBUG
        bpf_printk("[PASS] No correct Port");
    #endif

    return PASS;
}

static __always_inline __u8 isDNSQueryOrResponse(void *data, __u64 *offset, void *data_end, struct id *id)
{
    struct dns_header *header;
    header = data + *offset;
    
    *offset  += sizeof(struct dns_header);

    if (data + *offset > data_end)
    {
        #ifdef DEBUG
            bpf_printk("[DROP] No DNS header");
        #endif
        
        return DROP;
    }

    if (bpf_ntohs(header->questions) > 1)
    {
        #ifdef DEBUG
            bpf_printk("[PASS] Multiple queries %d", bpf_ntohs(header->questions));
        #endif
        
        return PASS;
    }

    id->id = header->id;

    if (header->flags >> DNS_QR_SHIFT ^ DNS_QUERY_TYPE)
        return RESPONSE_RETURN;
        
    return QUERY_RETURN;
}

static __always_inline __u8 getDomain(void *data, __u64 *offset, void *data_end, struct dns_domain *query)
{
    
    __builtin_memset(query->name, 0, DNS_KEY_DOMAIN_LENGTH);
    query->record_type = 0;

    __u8 *content = (data + *offset);

    *offset += sizeof(__u8);

    if (data + *offset > data_end)
        return DROP;

    if (*(content) == 0)
    {
        #ifdef DEBUG
            bpf_printk("[DROP] No Dns domain");
        #endif

        return DROP;
    }

    for (size_t size = 0; (size < MAX_DNS_NAME_LENGTH && *(content + size) != 0); size++)
    {
        query->name[size] =  *(char *)(content + size);
    
        if (data + ++(*offset) > data_end)
            return DROP;
    }

    content = data + *offset; // 0 Octect

    *offset += (sizeof(__u8) * 4);

    if (data + *offset > data_end)
        return DROP;

    query->record_type = bpf_ntohs(*((__u16 *) content));

    content += 2;

    if (bpf_htons(*((__u16 *) content)) ^ INTERNT_CLASS)
    {
        #ifdef DEBUG
            bpf_printk("[PASS] It's not a DNS query class IN");
        #endif

        return PASS;
    }
    
    return ACCEPT;
}

static __always_inline __u8 prepareResponse(void *data, __u64 *offset, void *data_end) {


    if (data + *offset > data_end)
    {
        #ifdef DEBUG
            bpf_printk("[DROP] Boundary exceded");
        #endif

        return DROP;
    }


    struct ethhdr *eth;
    eth = data;

    unsigned char tmp_mac[ETH_ALEN];

	__builtin_memcpy(tmp_mac, eth->h_source, ETH_ALEN);
	__builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

    struct iphdr *ipv4;
    ipv4 = data + sizeof(struct ethhdr);

    __be32 tmp_ip = ipv4->saddr;
	ipv4->saddr = ipv4->daddr;
	ipv4->daddr = tmp_ip;

    __u16 ipv4len = (data_end - data) - sizeof(struct ethhdr);
    ipv4->tot_len = bpf_htons(ipv4len);

    ipv4->check = calculate_ip_checksum(ipv4);

    struct udphdr *udp;
    udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

    __be16 tmp_port = udp->source;
	udp->source = udp->dest;
	udp->dest = tmp_port;

    __u16 udplen = (data_end - data) - sizeof(struct ethhdr) - sizeof(struct iphdr);
    udp->len = bpf_htons(udplen);

    udp->check = bpf_htons(UDP_NO_ERROR);

    return ACCEPT;
}

static __always_inline __u8 createDnsAnswer(void *data, __u64 *offset, void *data_end, struct a_record *record) {

    struct dns_header *header;
    
    header = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
    header->answer_count = bpf_htons(1);
    header->flags |= DNS_RESPONSE_TYPE << DNS_QR_SHIFT;
    header->flags |= DNS_RA << DNS_RA_SHIFT;

    struct dns_response *response;

    response = data + *offset;

    *offset += sizeof(struct dns_response);

    if (data + *offset > data_end)
    {
        #ifdef DEBUG
            bpf_printk("[DROP] No DNS answer");
        #endif

        return DROP;
    }

    response->query_pointer = bpf_htons(DNS_POINTER_OFFSET);
    response->class = bpf_htons(INTERNT_CLASS);
    response->record_type = bpf_htons(A_RECORD_TYPE);
    response->ttl = bpf_htonl(record->ttl);
    response->data_length = bpf_htons(sizeof(record->ip_addr.s_addr));
    response->ip = (record->ip_addr.s_addr);    

    return ACCEPT;
}

static __always_inline void createDnsQuery(void *data, __u64 *offset, void *data_end, struct query_owner *owner, __be32 ip_dest) {

    struct ethhdr *eth;
    eth = data;

    char temp_mac[ETH_ALEN];

	__builtin_memcpy(temp_mac, eth->h_source, ETH_ALEN);
	__builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, temp_mac, ETH_ALEN);

    struct iphdr *ipv4;
    ipv4 = data + sizeof(struct ethhdr);

    owner->ip_address = ipv4->saddr;
	ipv4->saddr = ipv4->daddr;
	ipv4->daddr = ip_dest;

    ipv4->check = calculate_ip_checksum(ipv4);

    struct udphdr *udp;
    udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

    udp->check = bpf_htons(UDP_NO_ERROR);
}

static __always_inline __u8 prepareRecursiveResponse(void *data, __u64 *offset, void *data_end, struct query_owner *owner) {

    if (data + *offset > data_end)
    {
        #ifdef DEBUG
            bpf_printk("[DROP] Boundary exceded");
        #endif

        return DROP;
    }

    struct ethhdr *eth;
    eth = data;

    char temp_mac[ETH_ALEN];
    
	__builtin_memcpy(temp_mac, eth->h_source, ETH_ALEN);
	__builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, temp_mac, ETH_ALEN);

    struct iphdr *ipv4;
    ipv4 = data + sizeof(struct ethhdr);

	ipv4->saddr = ipv4->daddr;
	ipv4->daddr = owner->ip_address;

    ipv4->check = calculate_ip_checksum(ipv4);

    struct udphdr *udp;
    udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

    udp->check = bpf_htons(UDP_NO_ERROR);

    return ACCEPT;
}

static __always_inline __u8 getDNSAnswer(void *data, __u64 *offset, void *data_end, struct a_record *record) {

    struct dns_header *header;
    
    header = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

    if (!header->answer_count)
        return ACCEPT_NO_ANSWER;

    struct dns_response *response;

    response = data + *offset;

    *offset += sizeof(struct dns_response);

    if (data + *offset > data_end)
    {
        #ifdef DEBUG
            bpf_printk("[DROP] No DNS answer");
        #endif

        return DROP;
    }

    record->ip_addr.s_addr = response->ip;
    record->ttl = response->ttl;

    return ACCEPT;
}

// static __always_inline __u32 findOwnerServer(struct dns_domain *query) { 

//     size_t curr = 0;

//     for (size_t i = 0; i < 10 && curr < DNS_KEY_DOMAIN_LENGTH && DNS_KEY_DOMAIN_LENGTH - curr >= MAX_DNS_NAME_LENGTH && query->name[curr] != 0; i++)
//     {
//         struct ns_record *nsrecord;

//         nsrecord = bpf_map_lookup_elem(&cache_nsrecords, &query->name[curr]);

//         if (nsrecord)
//         {
//             struct a_record *arecord = bpf_map_lookup_elem(&cache_arecords, nsrecord->name);

//             if (arecord)
//                 return arecord->ip_addr.s_addr;
//         }

//         curr += query->name[curr] + 1;
//     }

//     return recursive_server_ip;
// }


static __always_inline __u8 typeOfResponse(void *data, void *data_end) { 
    

    struct dns_header *header;    
    header = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

    if (header->answer_count)
        return ANSWER;

    if (header->name_servers && header->additional_records)
        return ADDITIONAL;

    if (header->name_servers)
        return NAMESERVERS;

    return ANSWER;
}

// static __always_inline __u32 getAuthoritative(void *data, __u64 *offset, void *data_end) {

//     struct dns_header *header;    
//     header = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

//     __u8 *content = data + *offset;
 
//     for (size_t i = 0; i < header->name_servers; i++)
//     {
//         *offset += 12;

//         if (data + *offset > data_end)
//             return DROP;

//         content += 10;

//         *offset +=  *((__u16 *) content);

//         if (data + *offset > data_end)
//             return DROP;

//         content = data + *offset;
//     }

//     *offset += 16;

//     if (data + *offset > data_end)
//         return DROP;

//     content += 12;

//     return *((__u32 *) content);
    
// }

SEC("xdp")
int dns_filter(struct xdp_md *ctx) {

    void *data_end = (void*) (long) ctx->data_end;
    void *data = (void*) (long) ctx->data;

    __u64 offset_h; // Desclocamento d e bits para verificar as informações do pacote

    switch (isIPV4(data, &offset_h, data_end))
    {
        case DROP:
            return XDP_DROP;
        case PASS:
            return XDP_PASS;
        default:
            #ifdef defined(DEBUG) || defined(OUTPUT)
                bpf_printk("[XDP] It's IPV4");
            #endif
            break;
    }

    struct query_owner owner;

    switch (isValidUDP(data, &offset_h, data_end, &owner))
    {
        case DROP:
            return XDP_DROP;
        case PASS:
            return XDP_PASS;
        default:
            #ifdef defined(DEBUG) || defined(OUTPUT)
                bpf_printk("[XDP] It's UDP");
            #endif
            break;
    }

    struct dns_query query;

    __u8 port53 = isPort53(data, &offset_h, data_end, &query.id);

    switch (port53)
    {
        case DROP:
            return XDP_DROP;
        case PASS:
            return XDP_PASS;
        default:
            #ifdef defined(DEBUG) || defined(OUTPUT)
                bpf_printk("[XDP] It's Port 53");
            #endif  
            break;
    }

    __u8 query_response = isDNSQueryOrResponse(data, &offset_h, data_end, &query.id);

    switch (query_response)
    {
        case DROP:
            return XDP_DROP;
        case PASS:
            return XDP_PASS;
        default:
            #ifdef defined(DEBUG) || defined(OUTPUT)
                bpf_printk("[XDP] It's DNS");
            #endif
            break;
    }

    switch (getDomain(data, &offset_h, data_end, &query.query))
    {
        case DROP:
            return XDP_DROP;
        case PASS:
            return XDP_PASS;
        default:
            #if defined(DEBUG) || defined(OUTPUT) || defined(DOMAIN)
                bpf_printk("%d", query.query.name[0]);
                bpf_printk("[XDP] Domain requested: %s", query.query.name);
            #endif

            break;
    }

    if ((query_response == QUERY_RETURN) && (port53 == TO_DNS_PORT))
    {
        #ifdef defined(DEBUG) || defined(OUTPUT)
            bpf_printk("[XDP] It's a query");
        #endif

        switch (query.query.record_type)
        {
            case A_RECORD_TYPE:

                struct a_record *arecord;

                arecord = bpf_map_lookup_elem(&cache_arecords, &query.query.name);

                if (arecord)
                {

                    if (bpf_xdp_adjust_tail(ctx, sizeof(struct dns_response)) < 0)
                    {
                        #ifdef DEBUG
                            bpf_printk("[XDP] It was't possible to resize the packet");
                        #endif
                        
                        return XDP_DROP;
                    }

                    data = (void*) (long) ctx->data;
                    data_end = (void*) (long) ctx->data_end;

                    switch (prepareResponse(data, &offset_h, data_end))
                    {
                        case DROP:
                            return XDP_DROP;
                        default:
                            #ifdef DEBUG
                                bpf_printk("[XDP] Headers updated");
                            #endif  
                            break;
                    }

                    switch (createDnsAnswer(data, &offset_h, data_end, arecord))
                    {
                        case DROP:
                            return XDP_DROP;
                        default:
                            #ifdef DEBUG
                                bpf_printk("[XDP] Answer created");
                            #endif  
                            break;
                    }
                }

                else 
                {       

                    // __u32 ip = findOwnerServer(&query.query);

                    __u32 ip = recursive_server_ip;

                    bpf_map_update_elem(&recursive_queries, (struct rec_query_key *) &query, &owner, 0);
                    
                    createDnsQuery(data, &offset_h, data_end, &owner, ip);
                }

                return XDP_TX;
        
        default:
            break;
        }

    }

    else if (query_response == RESPONSE_RETURN && port53 == FROM_DNS_PORT)
    {
        #ifdef DOMAIN
            bpf_printk("[XDP] It's a response");
        #endif

        // struct hop_query_value *last_query;
        // last_query = bpf_map_lookup_elem(&hop_queries, (struct rec_query_domain *) &query);

        // if (last_query > 0)
        // {
        //     return XDP_TX;
        // }

        struct query_owner *owner;
        owner = bpf_map_lookup_elem(&recursive_queries, (struct rec_query_key *) &query);

        if (owner > 0)
        {

            #ifdef DOMAIN
                bpf_printk("[XDP] It's a recursive query");
            #endif

            switch (typeOfResponse(data, data_end))
            {
                case ANSWER:
                    switch (prepareRecursiveResponse(data, &offset_h, data_end, owner))
                    {
                        case DROP:
                            return XDP_DROP;
                        default:
                            #ifdef DEBUG
                                bpf_printk("[XDP] Dns recursive response created");
                            #endif  
                            break;
                    }
                    
                    bpf_map_delete_elem(&recursive_queries, &query);

                    struct a_record cache_record;

                    switch (getDNSAnswer(data, &offset_h, data_end, &cache_record))
                    {
                        case DROP:
                            return XDP_DROP;
                        case ACCEPT_NO_ANSWER:
                            #ifdef DEBUG
                                bpf_printk("[XDP] No DNS answer");
                            #endif 
                            break;
                        default:
                            bpf_map_update_elem(&cache_arecords, &query.query, &cache_record, 0);
                            #ifdef DEBUG
                                bpf_printk("[XDP] Record obtained");
                            #endif  
                            break;
                    }        

                    break;

                case ADDITIONAL:

                    #ifdef DOMAIN
                        bpf_printk("%s", data + offset_h);
                    #endif  
                    

                    // __u32 ip = getAuthoritative(data, &offset_h, data_end);

                    // bpf_map_update_elem(&recursive_queries, (struct rec_query_domain *) &query, &owner, 0);
                    
                    // createDnsQuery(data, &offset_h, data_end, &owner, ip);



                
                default:
                    break;
            }

            return XDP_TX;
        }

        return XDP_PASS;
    }

    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";