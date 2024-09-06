#include "in.h"
#include "ip.h"
#include "udp.h" // In udp we verifiy if the source port is 53
#include "if_vlan.h" // Essential to verify the ip type
#include "if_ether.h" // Essential for ethernet headers
#include "if_packet.h"
#include "bpf.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "dns.h"

#define DEBUG

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 1500000);
        __uint(key_size, sizeof(struct dns_query));
        __uint(value_size, sizeof(struct a_record));
        __uint(pinning, LIBBPF_PIN_BY_NAME);

} dns_records SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 10);
        __uint(key_size, sizeof(struct query_id));
        __uint(value_size, sizeof(struct query_owner));
        __uint(pinning, LIBBPF_PIN_BY_NAME);

} recursive_queries SEC(".maps");

__be32 recursive_server_ip;
unsigned char recursive_server_mac[ETH_ALEN];

static __always_inline void print_ip(__u64 ip) {

    __u8 fourth = ip >> 24;
    __u8 third = (ip >> 16) & 0xFF;
    __u8 second = (ip >> 8) & 0xFF;
    __u8 first = ip & 0xFF;

    #ifdef DEBUG
        bpf_printk("IP: %d.%d.%d.%d", first, second, third, fourth);
    #endif

}

// static __always_inline __u64 ip_to_int(char *ip) {

//     __u64 final_sum = 0;
//     __u8 cont = 0;

//     __u16 octet = 256;
//     __u8 octet_cont = 0;
    
//     __u8 digits[3];

//     #pragma unroll
//     for (__u8 i = 0; i < 15; i++)
//     {
        
//         if(ip[i] == '.' || ip[i] == '\0' || cont == 3)
//         {
//             __u16 p, sum = 0;

//             #pragma unroll
//             for (__u8 j = 0; j < 3; j++)
//             {
//                 if (cont)
//                 {
//                     p = digits[j];

//                     #pragma unroll
//                     for (__u8 k = 0; k < 2; k++) 
//                     {
//                         if (cont - 1 > k)
//                             p *= 10;
//                     }

//                     cont--;

//                     sum += p;
//                 }
//             }
                
//             __u64 octet_p = 1;
//             for (__u8 j = 0; j < 3; j++)
//             {
//                 if(octet_cont > j)
//                     octet_p *= octet;
//             }

//             octet_cont++;
//             final_sum += (sum*octet_p);

//         }

//         else {
//             digits[cont] = ip[i] - 48;
//             cont++;
//         }
//     }   

//     return final_sum;
// }

static inline uint16_t calculate_ip_checksum(void *data, void *data_end)
{
    struct iphdr *ipv4;
    ipv4 = data + sizeof(struct ethhdr);
    void *pointer = data + sizeof(struct ethhdr);

    uint32_t accumulator = 0;
    for (int i = 0; i < sizeof(struct iphdr); i += 2)
    {
        uint16_t val;
        //If we are currently at the checksum_location, set to zero
        val = (&ipv4->check != (pointer + i)) ? *(uint16_t *)(pointer + i) : 0;

        accumulator += val;

        if (accumulator > 0xFFFF)
            accumulator = (accumulator & 0xFFFF) + (accumulator >> 16);
    }

    
    uint16_t chk = ~accumulator;

    #ifdef DEBUG
        bpf_printk("Checksum: %u", chk);
    #endif

    return chk;
}

static __always_inline int isIPV4(void *data, __u64 *offset, void *data_end)
{

    struct ethhdr *eth = data; // Cabeçalho da camada ethrenet

    *offset = sizeof(struct ethhdr);

    if (data + *offset > data_end)
    {
        #ifdef DEBUG
            bpf_printk("[DROP] No ethernet frame");
        #endif

        return 0;
    }

    __u16 ip_type; // Tipo de ip, esta contido na camada ethrenet
    ip_type = eth->h_proto;

    if(ip_type ^ bpf_htons(IPV4))
    {
        #ifdef DEBUG
            bpf_printk("[DROP] Ethernet type isn't IPV4. IP type: %d", ip_type);
        #endif
        return 0;
    }

    return 1;
}

static __always_inline int isValidUDP(void *data, __u64 *offset, void *data_end)
{
    struct iphdr *ipv4;
    ipv4 = data + *offset;

    *offset += sizeof(struct iphdr);

    if (data + *offset > data_end)
    {
        #ifdef DEBUG
            bpf_printk("[DROP] No ip frame");
        #endif
        return 0;
    }
    
    if (ipv4->frag_off & IP_FRAGMENTET)
    {
        #ifdef DEBUG
            bpf_printk("[DROP] Frame fragmented");
        #endif
        return 0;
    }

    __u8 transport_protocol;
    transport_protocol = ipv4->protocol;

    if (transport_protocol ^ UDP_PROTOCOL)
    {
        #ifdef DEBUG
            bpf_printk("[DROP] Ip protocol is TCP. Protocol: %d", transport_protocol);
        #endif

        return 0;
    }

    return 1;
}

static __always_inline int isPort53(void *data, __u64 *offset, void *data_end)
{
    struct udphdr *udp;
    udp = data + *offset;
    *offset += sizeof(struct udphdr);

    if(data + *offset > data_end)
    {
        #ifdef DEBUG
            bpf_printk("[DROP] No UDP datagram");
        #endif
        return 0;
    }

    if (bpf_ntohs(udp->dest) ^ DNS_PORT)
    {
        #ifdef DEBUG
            bpf_printk("[DROP] UDP datagram isn't port 53. Port: %d ", bpf_ntohs(udp->dest));
        #endif
        return 0;
    }

    return 1;
}

static __always_inline int isDNSQuery(void *data, __u64 *offset, void *data_end, struct query_id *query)
{
    struct dns_header *header;
    header = data + *offset;
    
    *offset  += sizeof(struct dns_header);

    if (data + *offset > data_end)
    {
        #ifdef DEBUG
            bpf_printk("[DROP] No DNS header");
        #endif
        
        return 0;
    }

    query->id = header->id;

    if (header->flags >> DNS_QR_SHIFT ^ DNS_QUERY_TYPE)
    {

        #ifdef DEBUG
            bpf_printk("[DROP] It's not a DNS query");
        #endif
        
        return 0;
    }

    return 1;
}

static __always_inline int getDomain(void *data, __u64 *offset, void *data_end, struct dns_query *query)
{
    
    __builtin_memset(query->name, 0, MAX_DNS_NAME_LENGTH);
    query->class = 0; query->record_type = 0;

    __u8 *content = (data + *offset), size = 0;

    *offset += sizeof(__u8);

    if (data + *offset > data_end)
        return 0;
    
    size = *(content);

    if (size == 0)
    {
        #ifdef DEBUG
            bpf_printk("[DROP] No Dns domain");
        #endif

        return 0;
    }
    
    *offset += sizeof(__u8);

    if (data + *offset > data_end)
        return 0;
    
    content++;

    for (size_t i = 0; (i < MAX_DNS_NAME_LENGTH && *(content + i) != 0); i++)
    {
        if(size == 0)
        {
            query->name[i] = '.';

            size = *(content + i);
        }

        else
        {
            query->name[i] =  *(char *)(content + i);
            size--;
        }

        *offset += sizeof(__u8);

        if (data + *offset > data_end)
            return 0;
    }

    content = data + *offset; // 0 Octect

    *offset += (sizeof(__u8) * 4);

    if (data + *offset > data_end)
        return 0;

    query->record_type = bpf_ntohs(*((uint16_t *) content));

    if (query->record_type ^ A_RECORD_TYPE)
    {
        #ifdef DEBUG
            bpf_printk("[DROP] It's not a DNS query type A");
        #endif
        return 0;
    }
    
    content += 2;

    query->class = bpf_htons(*((uint16_t *) content));

    if (query->class ^ INTERNT_CLASS)
    {
        #ifdef DEBUG
            bpf_printk("[DROP] It's not a DNS query class IN");
        #endif
        return 0;
    }
    
    return 1;
}

static __always_inline int prepareResponse(void *data, __u64 *offset, void *data_end) {


    if (data + *offset > data_end)
    {
        #ifdef DEBUG
            bpf_printk("[DROP] Boundary exceded");
        #endif

        return 0;
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

    uint16_t ipv4len = (data_end - data) - sizeof(struct ethhdr);
    ipv4->tot_len = bpf_htons(ipv4len);

    ipv4->check = calculate_ip_checksum(data, data_end);

    struct udphdr *udp;
    udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

    __be16 tmp_port = udp->source;
	udp->source = udp->dest;
	udp->dest = tmp_port;

    uint16_t udplen = (data_end - data) - sizeof(struct ethhdr) - sizeof(struct iphdr);
    udp->len = bpf_htons(udplen);

    udp->check = bpf_htons(UDP_NO_ERROR);

    return 1;
}

static __always_inline int createDnsAnswer(void *data, __u64 *offset, void *data_end, struct a_record *record) {

    __be16 answer_count;

    if (record > 0)
    {
        answer_count = 1;

        struct dns_response *response;

        response = data + *offset;

        *offset += sizeof(struct dns_response);

        if (data + *offset > data_end)
        {
            #ifdef DEBUG
                bpf_printk("[DROP] No DNS answer");
            #endif

            return 0;
        }

        response->query_pointer = bpf_htons(DNS_POINTER_OFFSET);
        response->class = bpf_htons(INTERNT_CLASS);
        response->record_type = bpf_htons(A_RECORD_TYPE);
        response->ttl = bpf_htonl(record->ttl);
        response->data_length = bpf_htons(sizeof(record->ip_addr.s_addr));
        response->ip = (record->ip_addr.s_addr);
    }

    else answer_count = 0;

    struct dns_header *header;
    
    header = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
    header->answer_count = bpf_htons(answer_count);
    header->flags |= DNS_RESPONSE_TYPE << DNS_QR_SHIFT;
    header->flags |= DNS_RA << DNS_RA_SHIFT;

    return 1;
}

static __always_inline int createDnsQuery(void *data, __u64 *offset, void *data_end, struct query_owner *owner) {

    if (data + *offset > data_end)
    {
        #ifdef DEBUG
            bpf_printk("[DROP] Boundary exceded");
        #endif

        return 0;
    }

    struct ethhdr *eth;
    eth = data;

	__builtin_memcpy(owner->mac_address, eth->h_source, ETH_ALEN);
	__builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, recursive_server_mac, ETH_ALEN);

    #ifdef DEBUG
        bpf_printk("%s", recursive_server_mac);
        bpf_printk("%s", eth->h_dest);
    #endif

    struct iphdr *ipv4;
    ipv4 = data + sizeof(struct ethhdr);

    owner->ip_address = ipv4->saddr;
	ipv4->saddr = ipv4->daddr;
	ipv4->daddr = recursive_server_ip;

    print_ip(ipv4->daddr);

    // uint16_t ipv4len = (data_end - data) - sizeof(struct ethhdr);
    // ipv4->tot_len = bpf_htons(ipv4len);

    ipv4->check = calculate_ip_checksum(data, data_end);

    struct udphdr *udp;
    udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

    // __be16 tmp_port = udp->source;
	// udp->source = udp->dest;
	// udp->dest = tmp_port;

    // uint16_t udplen = (data_end - data) - sizeof(struct ethhdr) - sizeof(struct iphdr);
    // udp->len = bpf_htons(udplen);

    udp->check = bpf_htons(UDP_NO_ERROR);

    return 1;
}

SEC("xdp")
int dns_filter(struct xdp_md *ctx) {

    void *data_end = (void*) (long) ctx->data_end;
    void *data = (void*) (long) ctx->data;

    __u64 offset_h; // Desclocamento d e bits para verificar as informações do pacote

    if(isIPV4(data, &offset_h, data_end))
    {
        #ifdef DEBUG
            bpf_printk("Its IPV4");
        #endif
    }

    else
        return XDP_PASS;


    if(isValidUDP(data, &offset_h, data_end))
    {
        #ifdef DEBUG
            bpf_printk("Its UDP");
        #endif
    }

    else
        return XDP_PASS;

    if(isPort53(data, &offset_h, data_end))
    {
        #ifdef DEBUG
            bpf_printk("Its Port 53");
        #endif
    }

    else
        return XDP_PASS;

    struct query_id query;

    if (isDNSQuery(data, &offset_h, data_end, &query))
    {
        #ifdef DEBUG
            bpf_printk("Its DNS Query");
        #endif
    }

    else
        return XDP_DROP;

    if(getDomain(data, &offset_h, data_end, &query.dquery))
    {
        #ifdef DEBUG
            bpf_printk("Domain requested: %s", query.dquery.name);
            bpf_printk("Domain requested");
            bpf_printk("Domain type: %d", query.dquery.record_type);
            bpf_printk("Domain class: %d", query.dquery.class);
        #endif
    }

    else 
        return XDP_DROP;
    
    struct a_record *record;
    record = bpf_map_lookup_elem(&dns_records, &query.dquery);

    if (record > 0)
    {

        int delta = sizeof(struct dns_response);

        if (bpf_xdp_adjust_tail(ctx, delta) < 0)
        {
            #ifdef DEBUG
                bpf_printk("It was't possible to resize the packet");
            #endif
            
            return XDP_DROP;
        }

        data = (void*) (long) ctx->data;
        data_end = (void*) (long) ctx->data_end;

        if(prepareResponse(data, &offset_h, data_end))
        {
            #ifdef DEBUG
                bpf_printk("Headers updated");
            #endif
        }

        else 
            return XDP_DROP;


        if(createDnsAnswer(data, &offset_h, data_end, record))
        {
            #ifdef DEBUG
                bpf_printk("Dns answer created");
            #endif
        }

        else
            return XDP_DROP;
    }


    else 
    {       
        struct query_owner owner;

        if(createDnsQuery(data, &offset_h, data_end, &owner))
        {
            #ifdef DEBUG
                bpf_printk("Dns dns query");
            #endif
        }

        else
            return XDP_DROP;

        bpf_map_update_elem(&recursive_queries, &query, &owner, 0);
    }

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";