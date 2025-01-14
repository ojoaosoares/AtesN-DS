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

#define DOMAIN

struct {
        __uint(type, BPF_MAP_TYPE_PROG_ARRAY); 
        __uint(max_entries, 5);                
        __uint(key_size, sizeof(__u32)); 
        __uint(value_size, sizeof(__u32));       
} tail_programs SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 100);
        __uint(key_size, sizeof(struct curr_query));
        __uint(value_size, sizeof(struct dns_query));

} curr_queries SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 100);
        __uint(key_size, sizeof(struct rec_query_key));
        __uint(value_size, sizeof(struct query_owner));

} recursive_queries SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 100);
        __uint(key_size, sizeof(struct rec_query_key));
        __uint(value_size, sizeof(struct dns_domain));

} hop_queries SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_LRU_HASH);
        __uint(max_entries, 100);
        __uint(key_size, sizeof(char[MAX_DNS_NAME_LENGTH]));
        __uint(value_size, sizeof(struct a_record));

} cache_arecords SEC(".maps");

// struct {
//         __uint(type, BPF_MAP_TYPE_LRU_HASH);
//         __uint(max_entries, 1500000);
//         __uint(key_size, sizeof(char[DNS_KEY_DOMAIN_LENGTH - (MAX_DNS_NAME_LENGTH - 2)]));
//         __uint(value_size, sizeof(struct ns_record));

// } cache_nsrecords SEC(".maps");

__u32 recursive_server_ip;

unsigned char proxy_mac[ETH_ALEN];

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

static __always_inline __u8 isValidUDP(void *data, __u64 *offset, void *data_end)
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

    return ACCEPT;
}

static __always_inline __u8 isPort53(void *data, __u64 *offset, void *data_end)
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

    #ifdef DOMAIN
        bpf_printk("[XDP] Flags %d %d", bpf_ntohs(header->flags), header->flags);
    #endif

    if (bpf_ntohs(header->flags) & (1 << 15))
    {
        if (bpf_ntohs(header->answer_count) || (bpf_ntohs(header->flags) & 0x000F) ^ 0)
            return RESPONSE_RETURN;

        if (bpf_ntohs(header->additional_records) && bpf_ntohs(header->name_servers))
            return QUERY_ADDITIONAL_RETURN;

        if (bpf_ntohs(header->name_servers))
            return QUERY_NAMESERVERS_RETURN;

        return RESPONSE_RETURN;
    }
        

    if (bpf_ntohs(header->additional_records) && bpf_ntohs(header->name_servers))
        return QUERY_ADDITIONAL_RETURN;

    if (bpf_ntohs(header->name_servers))
        return QUERY_NAMESERVERS_RETURN;
	
    return QUERY_RETURN;
}

static __always_inline __u8 getDomain(void *data, __u64 *offset, void *data_end, struct dns_domain *query)
{
    __builtin_memset(query->name, 0, MAX_DNS_NAME_LENGTH);
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

    size_t size;

    for (size = 0; (size < MAX_DNS_NAME_LENGTH && *(content + size) != 0); size++)
    {
        query->name[size] =  *(char *)(content + size);
    
        if (data + ++(*offset) > data_end)
            return DROP;
    }

    query->domain_size = (__u8) size;

    content = data + *offset; // 0 Octect

    *offset += (sizeof(__u8) * 4);

    if (data + *offset > data_end)
        return DROP;

    query->record_type = bpf_ntohs(*((__u16 *) content));

    content += 2;

    if (bpf_ntohs(*((__u16 *) content)) ^ INTERNT_CLASS)
    {
        #ifdef DOMAIN
            bpf_printk("[PASS] It's not a DNS query class IN");
        #endif

        return PASS;
    }
    
    return ACCEPT;
}

static __always_inline __u16 getQueryId(void *data)
{
    struct dns_header *header = (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr));

    return header->id;
}

static __always_inline __u16 getSourcePort(void *data)
{
    struct udphdr *udp = (data + sizeof(struct ethhdr) + sizeof(struct iphdr));

    return bpf_ntohs(udp->source);
}

static __always_inline __u16 getDestPort(void *data)
{
    struct udphdr *udp = (data + sizeof(struct ethhdr) + sizeof(struct iphdr));

    return bpf_ntohs(udp->dest);
}

static __always_inline void getSourceMac(void *data, char mac[ETH_ALEN])
{
    struct ethhdr *eth = data;

    __builtin_memcpy(mac, eth->h_source, ETH_ALEN);
}

static __always_inline __u32 getSourceIp(void *data)
{
    struct iphdr *ipv4 = (data + sizeof(struct ethhdr));

    return ipv4->saddr;
}

static __always_inline __u8 formatNetworkAcessLayer(void *data, __u64 *offset, void *data_end, char mac[ETH_ALEN])
{
    struct ethhdr *eth = data;

    *offset = sizeof(struct ethhdr);

    if (data + *offset > data_end)
    {
        #ifdef DEBUG
            bpf_printk("[DROP] Boundary exceded");
        #endif

        return DROP;
    }

	__builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, mac, ETH_ALEN);

    return ACCEPT;
}

static __always_inline __u8 formatInternetLayer(void *data, __u64 *offset, void *data_end)
{
    struct iphdr *ipv4 = data + *offset;

    *offset += sizeof(struct iphdr);

    if (data + *offset > data_end)
    {
        #ifdef DEBUG
            bpf_printk("[DROP] Boundary exceded");
        #endif

        return DROP;
    }

    __be32 tmp_ip = ipv4->saddr;
	ipv4->saddr = ipv4->daddr;
	ipv4->daddr = tmp_ip;

    ipv4->tot_len = (__u16) bpf_htons((data_end - data) - sizeof(struct ethhdr));


    ipv4->check = calculate_ip_checksum(ipv4);

    return ACCEPT;
}

static __always_inline __u8 updateTransportChecksum(void *data, __u64 *offset, void *data_end)
{
    struct udphdr *udp = data + *offset;

    *offset += sizeof(struct udphdr);

    if (data + *offset > data_end)
    {
        #ifdef DEBUG
            bpf_printk("[DROP] Boundary exceded");
        #endif

        return DROP;
    }

    udp->check = bpf_htons(UDP_NO_ERROR);

    return ACCEPT;
}


static __always_inline __u8 formatTransportLayer(void *data, __u64 *offset, void *data_end)
{
    struct udphdr *udp = data + *offset;

    *offset += sizeof(struct udphdr);

    if (data + *offset > data_end)
    {
        #ifdef DEBUG
            bpf_printk("[DROP] Boundary exceded");
        #endif

        return DROP;
    }

    __be16 tmp_port = udp->source;
	udp->source = udp->dest;
	udp->dest = tmp_port;

    udp->len = (__u16) bpf_htons((data_end - data) - sizeof(struct ethhdr) - sizeof(struct iphdr));

    udp->check = bpf_htons(UDP_NO_ERROR);

    return ACCEPT;    
}

static __always_inline __u8 createDnsAnswer(void *data, __u64 *offset, void *data_end, __u32 ip, __u32 ttl, __u16 domain_size) {

    struct dns_header *header = data + *offset;

    *offset += sizeof(struct dns_header);

    if (data + *offset > data_end)
    {
        #ifdef DEBUG
            bpf_printk("[DROP] No DNS answer");
        #endif

        return DROP;
    }

    header->answer_count = bpf_htons(1);
    header->flags = bpf_htons(0x8180);
    header->name_servers = bpf_htons(0);
    header->additional_records = bpf_htons(0);

    struct dns_response *response = data + *offset + domain_size + 5;

    *offset += sizeof(struct dns_response) + domain_size + 5;

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
    response->ttl = bpf_htonl(ttl);
    response->data_length = bpf_htons(sizeof(ip));
    response->ip = (ip);    

    return ACCEPT;
}

static __always_inline __u8 createDnsQuery(void *data, __u64 *offset, void *data_end) {

    struct dns_header *header = data + *offset;

    *offset += sizeof(struct dns_header);

    if (data + *offset > data_end)
    {
        #ifdef DEBUG
            bpf_printk("[DROP] No DNS header");
        #endif

        return DROP;
    }

    header->questions = bpf_htons(1);
    header->answer_count = bpf_htons(0);
    header->name_servers = bpf_htons(0);
    header->additional_records = bpf_htons(0);
    header->flags = bpf_htons(0x0100);
    
    return ACCEPT;
}


static __always_inline __u8 returnToNetwork(void *data, __u64 *offset, void *data_end, __u32 ip_dest) {

    struct iphdr *ipv4 = data + *offset;

    *offset += sizeof(struct iphdr);

    if (data + *offset > data_end)
    {
        #ifdef DEBUG
            bpf_printk("[DROP] Boundary exceded");
        #endif

        return DROP;
    }

	ipv4->saddr = ipv4->daddr;
    ipv4->daddr = ip_dest;

    ipv4->tot_len = (__u16) bpf_htons((data_end - data) - sizeof(struct ethhdr));


    ipv4->check = calculate_ip_checksum(ipv4);

    return ACCEPT;
}

static __always_inline __u8 getDNSAnswer(void *data, __u64 *offset, void *data_end, struct a_record *record) {
    
    struct dns_header *header;
    
    header = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

    if (!bpf_ntohs(header->answer_count))
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
    record->ttl = bpf_ntohl(response->ttl);
    record->timestamp = bpf_ktime_get_ns() / 1000000000;

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

static __always_inline __u32 getAdditional(void *data, __u64 *offset, void *data_end, struct dns_domain *query, __u8 *subpointer) {

    struct dns_header *header;    
    header = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

    __u8 *content = data + *offset, count = 0;

    for (size_t size = 0; size < 500; size++)
    {
        if (data + ++(*offset) > data_end)
            return DROP;

        if ((*(content + size) & 0xC0) == 0xC0) {

            if (count < bpf_ntohs(header->name_servers))
            {
                if (data + (*offset) + 1 > data_end)
                    return DROP;

                __u16 pointer = (bpf_ntohs(*((__u16 *) (content + size))) & 0x3FFF) - sizeof(struct dns_header);

                if (pointer >= query->domain_size)    
                    continue;

                count++;
            }

            else
            {   
                if (data + (*offset) + 3 > data_end)
                    return DROP;

                if (bpf_ntohs(*((__u16 *) (content + size + 2))) ^ A_RECORD_TYPE)
                    continue;
                
                if (data + (*offset) + 15 > data_end)
                    return DROP;
                
                __u32 ip = *((__u32 *) (content + size + 12));

                if (data + (*offset) + 1 > data_end)
                            return DROP;
            
                __u16 pointer_autho = (bpf_ntohs(*((__u16 *) (content + size))) & 0x3FFF);

                if (pointer_autho > 500)
                    return DROP;

                __u8 *subdomain = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + pointer_autho - 12;

                if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + pointer_autho + 2 -12 > data_end)
                   return DROP;

                *subpointer = (__u8) (bpf_ntohs(*((__u16 *) (subdomain))) & 0x3FFF) - sizeof(struct dns_header);

                if (*subpointer >= query->domain_size)
                    return DROP;

                return ip;
            }
        }
    }
    
    return DROP;
}

static __always_inline __u8 getAuthoritative(void *data, __u64 *offset, void *data_end, struct dns_domain *autho, struct dns_domain *query) {

    __builtin_memset(autho->name, 0, MAX_DNS_NAME_LENGTH);

    __u64 newoff = *offset;

    __u8 *domain = data + *offset;

    *offset += query->domain_size + 15;

    __u8 *content = data + *offset;

    *offset += 2;
    
    if (data + *(offset) > data_end)
        return DROP;

    autho->domain_size = (__u8) bpf_ntohs(*((__u16 *) (content)));

    if (autho->domain_size > MAX_DNS_NAME_LENGTH)
        return DROP;

    content += 2;

    for (size_t size = 0; size < autho->domain_size; size++)
    {
        if (data + ++*(offset) > data_end)
            return DROP;

        if ((*(content + size) & 0xC0) == 0xC0)
        {
            if (data + (*offset) + 1 > data_end)
                return DROP;

            __u8 pointer = (bpf_ntohs(*((__u16 *) (content + size))) & 0x3FFF) - sizeof(struct dns_header);

            if (pointer >= query->domain_size)
                return DROP;

            #ifdef DOMAIN
                bpf_printk("[XDP] AQUII");
            #endif

            autho->domain_size += (query->domain_size - pointer) - 2;

            for (size_t i = 0; pointer + i < MAX_DNS_NAME_LENGTH; i++)
            {
                if (data + ++newoff > data_end)
                    return DROP;

                *(domain) = query->name[pointer + i];

                if (*(domain++) == 0)
                    break;
            }

            newoff = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header) + autho->domain_size;

            domain = data + newoff;

            if (data + ++newoff > data_end)
                return DROP;

            (*domain++) = 0;

            newoff += 4;

            if (data + newoff > data_end)
                return DROP;

            *((__u16 *) domain) = bpf_htons(A_RECORD_TYPE);

            domain += 2;

            *((__u16 *) domain) = bpf_htons(INTERNT_CLASS);

	    autho->record_type = A_RECORD_TYPE;

            return ACCEPT;
        }

        autho->name[size] = *(content + size);
        
        if (data +  ++newoff > data_end)
            return DROP;
            
        *(domain++) = autho->name[size];
    }

    autho->domain_size--;

    newoff += (sizeof(__u8) * 4);

    if (data + newoff > data_end)
        return DROP;

    *((__u16 *) domain) = bpf_htons(A_RECORD_TYPE);

    domain += 2;

    *((__u16 *) domain) = bpf_htons(INTERNT_CLASS);

    autho->record_type = A_RECORD_TYPE;

    return ACCEPT;
}

static __always_inline __u8 writeQuery(void *data, __u64 *offset, void *data_end, struct dns_domain *query) {

    __u8 *content = data + *offset;

    for (size_t i = 0; i < query->domain_size; i++)
    {
        if (data + ++*(offset) > data_end)
            return DROP;

        *(content + i) = query->name[i];
    }

    content = data + *offset;

    if (data + ++*(offset) > data_end)
            return DROP;

    *(content) = (__u8) 0;

    content++;

    (*offset) += 4;

    if (data + *(offset) > data_end)
        return DROP;

    (* (__u16 *) content) = bpf_htons(query->record_type);

    content += 2;

    (* (__u16 *) content) = bpf_htons(INTERNT_CLASS);

    return ACCEPT;
}

static __always_inline __u64 getTTl(__u64 timestamp) {

    __u64 now = bpf_ktime_get_ns() / 1000000000;

    if (now > timestamp)
        return now - timestamp;

    return (UINT64_MAX - timestamp) + now;
}


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
            #ifdef DEBUG
                bpf_printk("[XDP] It's IPV4");
            #endif
            break;
    }

    switch (isValidUDP(data, &offset_h, data_end))
    {
        case DROP:
            return XDP_DROP;
        case PASS:
            return XDP_PASS;
        default:
            #ifdef DEBUG
                bpf_printk("[XDP] It's UDP");
            #endif
            break;
    }

    switch (isPort53(data, &offset_h, data_end))
    {
        case DROP:
            return XDP_DROP;
        case PASS:
            return XDP_PASS;
        case TO_DNS_PORT:
            #ifdef DOMAIN
                bpf_printk("[XDP] It's to Port 53");
            #endif  
            bpf_tail_call(ctx, &tail_programs, 0);
        case FROM_DNS_PORT:
            #ifdef DOMAIN
                bpf_printk("[XDP] It's from Port 53");
            #endif  
            bpf_tail_call(ctx, &tail_programs, 1);
        default:
            break;
    }

    return XDP_PASS;
}


SEC("xdp")
int dns_query(struct xdp_md *ctx) {

    void *data_end = (void*) (long) ctx->data_end;
    void *data = (void*) (long) ctx->data;

    __u64 offset_h = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr); // Desclocamento d e bits para verificar as informações do pacote

    struct dns_query dnsquery;

    switch (isDNSQueryOrResponse(data, &offset_h, data_end, &dnsquery.id))
    {
        case DROP:
            return XDP_DROP;
        case PASS:
            return XDP_PASS;
        case QUERY_RETURN:
            #ifdef DOMAIN
                bpf_printk("[XDP] It's a query");
            #endif
            break;
        default:
            return XDP_DROP;
    }

    switch (getDomain(data, &offset_h, data_end, &dnsquery.query))
    {
        case DROP:
            return XDP_DROP;
        case PASS:
            return XDP_PASS;
        default:
            #ifdef DOMAIN
                bpf_printk("[XDP] Domain: %s", dnsquery.query.name);
		        bpf_printk("[XDP] Size: %u Type %u", dnsquery.query.domain_size, dnsquery.query.record_type);
                bpf_printk("[XDP] Id: %u Port %u", dnsquery.id.id, dnsquery.id.port);
            #endif

            break;
    }
    
    switch (dnsquery.query.record_type)
    {
        case A_RECORD_TYPE:

            struct a_record *arecord;

            arecord = bpf_map_lookup_elem(&cache_arecords, &dnsquery.query.name);

            if (arecord)
            {   
                #ifdef DOMAIN
                    bpf_printk("[XDP] Cache try");
                #endif
                
                __u64 diff = getTTl(arecord->timestamp);

                #ifdef DOMAIN
                    bpf_printk("[XDP] TTL: %llu Current: %llu", arecord->ttl, diff);
                #endif

                if (arecord->ttl > diff && (arecord->ttl) - diff >  MINIMUM_TTL)
                {
                    #ifdef DOMAIN
                        bpf_printk("[XDP] Cache hit");
                    #endif

                    __s16 newsize = (data + offset_h - data_end) + sizeof(struct dns_response);

                    if (bpf_xdp_adjust_tail(ctx, (int) newsize) < 0)
                    {
                        #ifdef DOMAIN
                            bpf_printk("[XDP] It was't possible to resize the packet");
                        #endif
                        
                        return XDP_DROP;
                    }

                    data = (void*) (long) ctx->data;
                    data_end = (void*) (long) ctx->data_end;

                    offset_h = 0;

                    switch (formatNetworkAcessLayer(data, &offset_h, data_end, proxy_mac))
                    {
                        case DROP:
                            return XDP_DROP;
                        default:
                            #ifdef DEBUG
                                bpf_printk("[XDP] Headers updated");
                            #endif  
                            break;
                    }

                    switch (formatInternetLayer(data, &offset_h, data_end))
                    {
                        case DROP:
                            return XDP_DROP;
                        default:
                            #ifdef DEBUG
                                bpf_printk("[XDP] Headers updated");
                            #endif  
                            break;
                    }

                    switch (formatTransportLayer(data, &offset_h, data_end))
                    {
                        case DROP:
                            return XDP_DROP;
                        default:
                            #ifdef DEBUG
                                bpf_printk("[XDP] Headers updated");
                            #endif  
                            break;
                    }

                    switch (createDnsAnswer(data, &offset_h, data_end, arecord->ip_addr.s_addr, arecord->ttl - diff, dnsquery.query.domain_size))
                    {
                        case DROP:
                            return XDP_DROP;
                        default:
                            #ifdef DEBUG
                                bpf_printk("[XDP] Answer created");
                            #endif  
                            break;
                    }

                    return XDP_TX;
                }

                else
                    bpf_map_delete_elem(&cache_arecords, &dnsquery.query.name);

            }

            struct query_owner owner;

            getSourceMac(data, &owner); owner.ip_address = getSourceIp(data); dnsquery.id.port = getSourcePort(data);

            if(bpf_map_update_elem(&recursive_queries, (struct rec_query_key *) &dnsquery, &owner, 0) < 0)
            {
                #ifdef DOMAIN
                    bpf_printk("[XDP] Recursive queries map error");
                #endif  

                return XDP_PASS;
            }

            __u32 ip = recursive_server_ip;

            offset_h = 0;

            switch (formatNetworkAcessLayer(data, &offset_h, data_end, proxy_mac))
            {
                case DROP:
                    return XDP_DROP;
                default:
                    #ifdef DEBUG
                        bpf_printk("[XDP] Headers updated");
                    #endif  
                    break;
            }
            
            switch(returnToNetwork(data, &offset_h, data_end, ip))
            {
                case DROP:
                    return XDP_DROP;
                default:
                    break;
            }


            switch(updateTransportChecksum(data, &offset_h, data_end))
            {
                case DROP:
                    return XDP_DROP;
                default:
                    break;
            }

            #ifdef DOMAIN
                bpf_printk("[XDP] Recursive Query created");
            #endif  
    

            return XDP_TX;
    
    default:
        break;
    }

    return XDP_PASS;
}


SEC("xdp")
int dns_response(struct xdp_md *ctx) {

    void *data_end = (void*) (long) ctx->data_end;
    void *data = (void*) (long) ctx->data;

    __u64 offset_h = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr); // Desclocamento d e bits para verificar as informações do pacote

    struct dns_query dnsquery;

    struct curr_query curr;

    __u8 query_response = isDNSQueryOrResponse(data, &offset_h, data_end, &dnsquery.id);

    #ifdef DOMAIN
        bpf_printk("[XDP] response %d", query_response);
    #endif

    switch (query_response)
    {
        case DROP:
            return XDP_DROP;
        case PASS:
            return XDP_PASS;
        default:
            #ifdef DOMAIN
                bpf_printk("[XDP] It's a response");
            #endif
            break;
    }

    curr.ip = getSourceIp(data); dnsquery.id.port = getDestPort(data); curr.id = dnsquery.id;

    switch (getDomain(data, &offset_h, data_end, &dnsquery.query))
    {
        case DROP:
            return XDP_PASS;
        case PASS:
            return XDP_PASS;
        default:
            #ifdef DOMAIN
                bpf_printk("[XDP] Domain: %s", dnsquery.query.name);
		        bpf_printk("[XDP] Size: %u Type %u", dnsquery.query.domain_size, dnsquery.query.record_type);
                bpf_printk("[XDP] Id: %u Port %u", dnsquery.id.id, dnsquery.id.port);
            #endif

            break;
    }

    struct query_owner *powner = bpf_map_lookup_elem(&recursive_queries, (struct rec_query_key *) &dnsquery);

    if (powner)
    {
        if (query_response == RESPONSE_RETURN)
        {
            bpf_map_delete_elem(&recursive_queries, &dnsquery);

            offset_h = 0;

            switch (formatNetworkAcessLayer(data, &offset_h, data_end, powner->mac_address))
            {
                case DROP:
                    return XDP_DROP;
                default:
                    #ifdef DEBUG
                        bpf_printk("[XDP] Headers updated");
                    #endif  
                    break;
            }
            
            switch(returnToNetwork(data, &offset_h, data_end, powner->ip_address))
            {
                case DROP:
                    return XDP_DROP;
                default:
                    break;
            }

            switch(updateTransportChecksum(data, &offset_h, data_end))
            {
                case DROP:
                    return XDP_DROP;
                default:
                    break;
            }

            offset_h += sizeof(struct dns_header) + dnsquery.query.domain_size + 5;
            
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
                    bpf_map_update_elem(&cache_arecords, &dnsquery.query.name, &cache_record, 0);
                    #ifdef DEBUG
                        bpf_printk("[XDP] Record obtained");
                    #endif  
                    break;
            }   

            #ifdef DOMAIN
                bpf_printk("[XDP] Recursive response returned");
            #endif

            return XDP_TX;
        }

        if (bpf_map_update_elem(&curr_queries, &curr, &dnsquery, 0) < 0)
        {
            #ifdef DOMAIN
                bpf_printk("[XDP] Curr queries map error");
            #endif  
            return XDP_PASS;
        }

        if (query_response == QUERY_ADDITIONAL_RETURN)
            bpf_tail_call(ctx, &tail_programs, 2);
        
        else if (query_response == QUERY_NAMESERVERS_RETURN)
            bpf_tail_call(ctx, &tail_programs, 3);

        return XDP_PASS;
    }

    struct dns_domain *lastdomain = bpf_map_lookup_elem(&hop_queries, (struct rec_query_key *) &dnsquery);

    if (lastdomain > 0)
    {   
        if (bpf_map_update_elem(&curr_queries, &curr, &dnsquery, 0) < 0)
        {
            #ifdef DOMAIN
                bpf_printk("[XDP] Curr queries map error");
            #endif  
            return XDP_PASS;
        }

        if (query_response == RESPONSE_RETURN)
            bpf_tail_call(ctx, &tail_programs, 4);

        else if (query_response == QUERY_ADDITIONAL_RETURN)
            bpf_tail_call(ctx, &tail_programs, 2);
        
        else if (query_response == QUERY_NAMESERVERS_RETURN)
            bpf_tail_call(ctx, &tail_programs, 3);
        
        return XDP_PASS;
    }

    return XDP_PASS;
}


SEC("xdp")
int dns_hop(struct xdp_md *ctx) {

    #ifdef DOMAIN
        bpf_printk("[XDP] Dns hop");
    #endif

    void *data = (void*) (long) ctx->data;
    void *data_end = (void*) (long) ctx->data_end;
    
    __u64 offset_h = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header); // Desclocamento d e bits para verificar as informações do pacote

    if (data + offset_h > data_end)
        return XDP_DROP;

    struct curr_query curr;
    
    curr.ip = getSourceIp(data); curr.id.port = getDestPort(data); curr.id.id = getQueryId(data);

    struct dns_query *query = bpf_map_lookup_elem(&curr_queries, &curr);

    if (query)
    {
        bpf_map_delete_elem(&curr_queries, &curr);

        if (data + offset_h > data_end)
            return XDP_DROP;

        __u8 pointer;    
    
        __u32 ip = getAdditional(data, &offset_h, data_end, &query->query, &pointer);
        
        switch (ip)
        {
            case DROP:
                return XDP_DROP;
            default:
                #ifdef DOMAIN
                    bpf_printk("[XDP] Subdomain %s", &query->query.name[pointer]);
                    bpf_printk("[XDP] Additional IP: %u", ip);
                #endif
                break;
        }   

        __s16 newsize = (__s16) ((data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header) +  query->query.domain_size + 5) - data_end);

        // alterHeaderSize(data, data_end, newsize);

        if (bpf_xdp_adjust_tail(ctx, (int) newsize) < 0)
        {
            #ifdef DOMAIN
                bpf_printk("[XDP] It was't possible to resize the packet");
            #endif
            
            return XDP_DROP;
        }

        data = (void*) (long) ctx->data;
        data_end = (void*) (long) ctx->data_end;

        offset_h = 0;

        switch (formatNetworkAcessLayer(data, &offset_h, data_end, proxy_mac))
        {
            case DROP:
                return XDP_DROP;
            default:
                #ifdef DEBUG
                    bpf_printk("[XDP] Headers updated");
                #endif  
                break;
        }
        
        switch(returnToNetwork(data, &offset_h, data_end, ip))
        {
            case DROP:
                return XDP_DROP;
            default:
                break;
        }

        switch (formatTransportLayer(data, &offset_h, data_end))
        {
            case DROP:
                return XDP_DROP;
            default:
                break;
        }

        switch(createDnsQuery(data, &offset_h, data_end))
        {
            case DROP:
                return XDP_DROP;
            default:
                break;
        }

        #ifdef DOMAIN
            bpf_printk("[XDP] Hop query created");
        #endif

        return XDP_TX;
    }

    return XDP_PASS;
}


SEC("xdp")
int dns_new_query(struct xdp_md *ctx) {

    #ifdef DOMAIN
        bpf_printk("[XDP] Dns new query");
    #endif

    void *data = (void*) (long) ctx->data;
    void *data_end = (void*) (long) ctx->data_end;
    
    __u64 offset_h = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header); // Desclocamento d e bits para verificar as informações do pacote

    if (data + offset_h > data_end)
        return XDP_DROP;

    struct curr_query curr;
    
    curr.ip = getSourceIp(data); curr.id.port = getDestPort(data); curr.id.id = getQueryId(data);

    struct dns_query *query = bpf_map_lookup_elem(&curr_queries, &curr);

    if (query) {

        bpf_map_delete_elem(&curr_queries, &curr);

        struct dns_query dnsquery; 
        
        dnsquery.id = curr.id;

        switch(getAuthoritative(data, &offset_h, data_end, &dnsquery.query, &query->query))
        {
            case DROP:
                #ifdef DOMAIN
                    bpf_printk("[XDP] Deu ruim");
                #endif
                return XDP_DROP;
            default:
                #ifdef DOMAIN
                    bpf_printk("[XDP] Authoritative %s", dnsquery.query.name);
		            bpf_printk("[XDP] Size: %u Type %u", dnsquery.query.domain_size, dnsquery.query.record_type);
                    bpf_printk("[XDP] Id: %u Port %u", dnsquery.id.id, dnsquery.id.port);
                #endif
                break;
        }

        
	if (bpf_map_update_elem(&hop_queries, (struct rec_query_key *) &dnsquery, &query->query, 0) < 0)
        {
            #ifdef DOMAIN
                bpf_printk("[XDP] Hop queries map error");
            #endif

            return XDP_PASS;
        }

        __s16 newsize = (__s16) ((data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header) +  dnsquery.query.domain_size + 5) - data_end);

        // alterHeaderSize(data, data_end, newsize);

        if (bpf_xdp_adjust_tail(ctx, (int) newsize) < 0)
        {
            #ifdef DOMAIN
                bpf_printk("[XDP] It was't possible to resize the packet");
            #endif
            
            return XDP_DROP;
        }

        data = (void*) (long) ctx->data;
        data_end = (void*) (long) ctx->data_end;

        offset_h = 0;      

        switch (formatNetworkAcessLayer(data, &offset_h, data_end, proxy_mac))
        {
            case DROP:
                return XDP_DROP;
            default:
                #ifdef DEBUG
                    bpf_printk("[XDP] Headers updated");
                #endif  
                break;
        }

        __u32 ip = recursive_server_ip;
        
        switch(returnToNetwork(data, &offset_h, data_end, ip))
        {
            case DROP:
                return XDP_DROP;
            default:
                break;
        }

        switch (formatTransportLayer(data, &offset_h, data_end))
        {
            case DROP:
                return XDP_DROP;
            default:
                break;
        }

        switch(createDnsQuery(data, &offset_h, data_end))
        {
            case DROP:
                return XDP_DROP;
            default:
                break;
        }

        #ifdef DOMAIN
            bpf_printk("[XDP] New query created");
        #endif

        return XDP_TX;
    }

    return XDP_PASS;
}


SEC("xdp")
int dns_backto_query(struct xdp_md *ctx) {

    #ifdef DOMAIN
        bpf_printk("[XDP] Dns Back to last Query");
    #endif

    void *data = (void*) (long) ctx->data;
    void *data_end = (void*) (long) ctx->data_end;
    
    __u64 offset_h = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header); // Desclocamento d e bits para verificar as informações do pacote

    if (data + offset_h > data_end)
        return XDP_DROP;

    struct curr_query curr;
    
    curr.ip = getSourceIp(data); curr.id.port = getDestPort(data); curr.id.id = getQueryId(data);

    struct dns_query *query = bpf_map_lookup_elem(&curr_queries, &curr);

    if (query) {

        bpf_map_delete_elem(&curr_queries, &curr);

        offset_h += query->query.domain_size + 5;

        if (data + offset_h > data_end)
            return XDP_DROP;

        struct dns_domain *lastdomain = bpf_map_lookup_elem(&hop_queries, query);

        if (lastdomain && lastdomain->domain_size <= MAX_DNS_NAME_LENGTH)
        {
            bpf_map_delete_elem(&hop_queries, query);

            __s16 newsize = (__s16) ((data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header)) - data_end) + lastdomain->domain_size + 5;

            // alterHeaderSize(data, data_end, newsize);
        
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
                    bpf_map_update_elem(&cache_arecords, &query->query.name, &cache_record, 0);
                    #ifdef DEBUG
                        bpf_printk("[XDP] Record obtained");
                    #endif  
                    break;
            }        

            if (bpf_xdp_adjust_tail(ctx, (int) newsize) < 0)
            {
                #ifdef DOMAIN
                    bpf_printk("[XDP] It was't possible to resize the packet");
                #endif
                
                return XDP_DROP;
            }

            data = (void*) (long) ctx->data;
            data_end = (void*) (long) ctx->data_end;

            offset_h = 0;      

            switch (formatNetworkAcessLayer(data, &offset_h, data_end, proxy_mac))
            {
                case DROP:
                    return XDP_DROP;
                default:
                    #ifdef DEBUG
                        bpf_printk("[XDP] Headers updated");
                    #endif  
                    break;
            }
            
            switch(returnToNetwork(data, &offset_h, data_end, cache_record.ip_addr.s_addr))
            {
                case DROP:
                    return XDP_DROP;
                default:
                    break;
            }

            switch (formatTransportLayer(data, &offset_h, data_end))
            {
                case DROP:
                    return XDP_DROP;
                default:
                    break;
            }

            switch(createDnsQuery(data, &offset_h, data_end))
            {
                case DROP:
                    return XDP_DROP;
                default:
                    break;
            }

            switch(writeQuery(data, &offset_h, data_end, lastdomain))
            {
                case DROP:
                    return XDP_DROP;
                default:
                    break;
            }

            #ifdef DOMAIN
                bpf_printk("[XDP] New back query created");
            #endif

            return XDP_TX;
        }
        
    }

    return XDP_PASS;
}


char _license[] SEC("license") = "GPL";
