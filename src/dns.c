#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_vlan.h> // Essential to verify the ip type
#include <linux/if_ether.h> // Essential for ethernet headers
#include <linux/if_packet.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "dns.h"

#define DOMAIN

struct {
        __uint(type, BPF_MAP_TYPE_PROG_ARRAY); 
        __uint(max_entries, 6);                
        __uint(key_size, sizeof(__u32)); 
        __uint(value_size, sizeof(__u32));       
} tail_programs SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 2000000);
        __uint(key_size, sizeof(struct curr_query));
        __uint(value_size, sizeof(struct dns_query));

} curr_queries SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 2000000);
        __uint(key_size, sizeof(struct rec_query_key));
        __uint(value_size, sizeof(struct query_owner));

} recursive_queries SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 7000000);
        __uint(key_size, sizeof(struct rec_query_key));
        __uint(value_size, sizeof(struct hop_query));

} new_queries SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_LRU_HASH);
        __uint(max_entries, 400000);
        __uint(key_size, sizeof(char[DNS_LIMIT]));
        __uint(value_size, sizeof(struct a_record));

} cache_arecords SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_LRU_HASH);
        __uint(max_entries, 250000);
        __uint(key_size, sizeof(char[DNS_LIMIT]));
        __uint(value_size, sizeof(struct a_record));

} cache_nsrecords SEC(".maps");

__u32 recursive_server_ip;

__u32 serverip;

unsigned char gateway_mac[ETH_ALEN];

static __always_inline __u64 getTTl(__u64 timestamp) {

    __u64 now = bpf_ktime_get_ns() / 1000000000 + 1;

    if (now > timestamp)
        return now - timestamp;

    return (UINT64_MAX - timestamp) + now;
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
        #ifdef FILTER
            bpf_printk("[DROP] No ethernet frame");
        #endif

        return DROP;
    }

    if(bpf_htons(eth->h_proto) ^ IPV4)
    {
        #ifdef FILTER
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
        #ifdef FILTER
            bpf_printk("[DROP] No ip frame");
        #endif
        return DROP;
    }
    
    if (ipv4->frag_off & IP_FRAGMENTET)
    {
        #ifdef FILTER
            bpf_printk("[PASS] Frame fragmented");
        #endif

        return PASS;
    }

    if (ipv4->protocol ^ UDP_PROTOCOL)
    {
        #ifdef FILTER
            bpf_printk("[PASS] Ip protocol isn't UDP. Protocol: %d", ipv4->protocol);
        #endif

        return PASS;
    }

    return ACCEPT;
}

static __always_inline __u8 isPort53(void *data, __u64 *offset, void *data_end)
{
    struct udphdr *udp = data + *offset;
    *offset += sizeof(struct udphdr);

    if(data + *offset > data_end)
    {
        #ifdef FILTER
            bpf_printk("[DROP] No UDP datagram");
        #endif
        return DROP;
    }

    if (bpf_ntohs(udp->dest) == DNS_PORT)
        return TO_DNS_PORT;
    
    if (bpf_ntohs(udp->source) == DNS_PORT)
        return FROM_DNS_PORT;

    #ifdef FILTER
        bpf_printk("[PASS] No correct Port");
    #endif

    return PASS;
}

static __always_inline __u8 isDNSQueryOrResponse(void *data, __u64 *offset, void *data_end, __u16 *id)
{
    struct dns_header *header;
    header = data + *offset;
    
    *offset  += sizeof(struct dns_header);

    if (data + *offset > data_end)
    {
        #ifdef FILTER
            bpf_printk("[DROP] No DNS header");
        #endif
        
        return DROP;
    }

    if (bpf_ntohs(header->questions) > 1)
    {
        #ifdef FILTER
            bpf_printk("[PASS] Multiple queries %d", bpf_ntohs(header->questions));
        #endif
        
        return PASS;
    }

    *id = header->id;

    #ifdef FILTER
        bpf_printk("[XDP] Flags %d %d", bpf_ntohs(header->flags), header->flags);
    #endif

    if (bpf_ntohs(header->flags) & (1 << 15))
    {
        if (bpf_ntohs(header->answer_count) || (bpf_ntohs(header->flags) & 0x000F) ^ 0 || bpf_ntohs(header->flags) & (1 << 10))
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
    __u8 *content = (data + *offset);

    *offset += sizeof(__u8);

    if (data + *offset > data_end)
        return DROP;

    if (*(content) == 0)
    {
        #ifdef DOMAIN
            bpf_printk("[DROP] No Dns domain");
        #endif

        return DROP;
    }

    __builtin_memset(query->name, 0, MAX_DNS_NAME_LENGTH);
    query->record_type = 0;

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

static __always_inline __u32 getSourceIp(void *data)
{
    struct iphdr *ipv4 = (data + sizeof(struct ethhdr));

    return ipv4->saddr;
}

static __always_inline __u8 formatNetworkAcessLayer(void *data, __u64 *offset, void *data_end)
{
    struct ethhdr *eth = data;

    *offset = sizeof(struct ethhdr);

    if (data + *offset > data_end)
    {
        #ifdef DOMAIN
            bpf_printk("[DROP] Boundary exceded");
        #endif

        return DROP;
    }

	__builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, gateway_mac, ETH_ALEN);

    return ACCEPT;
}

static __always_inline __u8 swapInternetLayer(void *data, __u64 *offset, void *data_end)
{
    struct iphdr *ipv4 = data + *offset;

    *offset += sizeof(struct iphdr);

    if (data + *offset > data_end)
    {
        #ifdef DOMAIN
            bpf_printk("[DROP] Boundary exceded");
        #endif

        return DROP;
    }

    __be32 tmp_ip = ipv4->saddr;
	ipv4->saddr = ipv4->daddr;
	ipv4->daddr = tmp_ip;

    ipv4->ttl = 255;

    ipv4->tot_len = (__u16) bpf_htons((data_end - data) - sizeof(struct ethhdr));

    ipv4->check = calculate_ip_checksum(ipv4);

    return ACCEPT;
}

static __always_inline __u8 keepTransportLayer(void *data, __u64 *offset, void *data_end)
{
    struct udphdr *udp = data + *offset;

    *offset += sizeof(struct udphdr);

    if (data + *offset > data_end)
    {
        #ifdef DOMAIN
            bpf_printk("[DROP] Boundary exceded");
        #endif

        return DROP;
    }

    udp->len = (__u16) bpf_htons((data_end - data) - sizeof(struct ethhdr) - sizeof(struct iphdr));

    udp->check = bpf_htons(UDP_NO_ERROR);

    return ACCEPT;
}

static __always_inline __u8 swapTransportLayer(void *data, __u64 *offset, void *data_end)
{
    struct udphdr *udp = data + *offset;

    *offset += sizeof(struct udphdr);

    if (data + *offset > data_end)
    {
        #ifdef DOMAIN
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

static __always_inline __u8 setDNSHeader(void *data, __u64 *offset, void *data_end) {

    struct dns_header *header = data + *offset;

    *offset += sizeof(struct dns_header);

    if (data + *offset > data_end)
    {
        #ifdef DOMAIN
            bpf_printk("[DROP] No DNS answer");
        #endif

        return DROP;
    }

    __u16 flags = bpf_ntohs(header->flags);
    
    flags |= 0x0080;
    flags &= ~0x0400; 

    header->flags = bpf_htons(flags);

    return ACCEPT;
}

static __always_inline __u8 createDNSAnswer(void *data, __u64 *offset, void *data_end, __u32 ip, __u32 ttl, __u8 status, __u16 domain_size) {

    struct dns_header *header = data + *offset;

    *offset += sizeof(struct dns_header);

    if (data + *offset > data_end)
    {
        #ifdef DOMAIN
            bpf_printk("[DROP] No DNS answer");
        #endif

        return DROP;
    }

    __u16 flags = 0x8180 + status;

    header->name_servers = bpf_htons(0);
    header->additional_records = bpf_htons(0);

    if (ip == 0)
    {
        flags = 0x8180 + 3;
        header->flags = bpf_htons(flags);
        header->answer_count = bpf_htons(0);
        
        return ACCEPT;
    }

    header->flags = bpf_htons(flags);
    header->answer_count = bpf_htons(1);

    *offset += domain_size + 5;
    
    struct dns_response *response = data + *offset;

    *offset += sizeof(struct dns_response);

    if (data + *offset > data_end)
    {
        #ifdef DOMAIN
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
        #ifdef DOMAIN
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
        #ifdef DOMAIN
            bpf_printk("[DROP] Boundary exceded");
        #endif

        return DROP;
    }

	ipv4->saddr = serverip;
    ipv4->daddr = ip_dest;

    ipv4->ttl = 255;

    ipv4->tot_len = (__u16) bpf_htons((data_end - data) - sizeof(struct ethhdr));

    ipv4->check = calculate_ip_checksum(ipv4);

    return ACCEPT;
}

static __always_inline __u8 getDNSAnswer(void *data, __u64 *offset, void *data_end, struct a_record *record) {
    
    struct dns_header *header;
    
    header = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

    struct dns_response *response;

    response = data + *offset;

    if ((bpf_ntohs(header->flags) & 0x000F) == 2 || (bpf_ntohs(header->flags) & 0x000F) == 5)
        return ACCEPT_NO_ANSWER;

    if (bpf_ntohs(header->answer_count))
    {
        *offset += sizeof(struct dns_response);

        if (data + *offset > data_end)
        {
            #ifdef DOMAIN
                bpf_printk("[DROP] No DNS answer");
            #endif

            return DROP;
        }

        if(bpf_ntohs(response->record_type) == CNAME_RECORD_TYPE && bpf_ntohs(header->answer_count) > 1)
        {
            #ifdef DOMAIN
                bpf_printk("[DROP] CNAME record");
            #endif

            if (bpf_ntohs(response->data_length) > MAX_DNS_NAME_LENGTH)
                return ACCEPT_NO_ANSWER;

            *offset += bpf_ntohs(response->data_length) - 4;

            response = data + *offset;

            *offset += sizeof(struct dns_response);

            if (data + *offset > data_end)
            {
                #ifdef DOMAIN
                    bpf_printk("[DROP] No DNS answer");
                #endif

                return DROP;
            }
        }

        if (bpf_ntohs(response->class) ^ INTERNT_CLASS)
            return ACCEPT_NO_ANSWER;

        if (bpf_ntohs(response->record_type) ^ A_RECORD_TYPE)
            return ACCEPT_NO_ANSWER;

        record->ip = response->ip;
        record->ttl = bpf_ntohl(response->ttl);
        record->timestamp = bpf_ktime_get_ns() / 1000000000;
        record->status = (bpf_ntohs(header->flags) & 0x000F);

        #ifdef DOMAIN
            bpf_printk("[XDP] Answer IP: %u", record->ip);
            bpf_printk("[XDP] Answer TTL: %u", record->ttl);
        #endif
        
        return ACCEPT;
    }

    if (bpf_ntohs(header->name_servers))
    {
        *offset += sizeof(struct dns_response);

        if (data + *offset > data_end)
        {
            #ifdef DOMAIN
                bpf_printk("[DROP] No DNS answer");
            #endif

            return DROP;
        }

        if (bpf_ntohs(response->class) ^ INTERNT_CLASS)
            return ACCEPT_NO_ANSWER;

        if(bpf_ntohs(response->record_type) ^ SOA_RECORD_TYPE)
            return ACCEPT_NO_ANSWER;

        record->ip = 0;
        record->ttl = bpf_ntohl(response->ttl);
        record->timestamp = bpf_ktime_get_ns() / 1000000000;
        record->status = (bpf_ntohs(header->flags) & 0x000F);

        return ACCEPT;  
    }
    
    return ACCEPT_NO_ANSWER;
}

static __always_inline __u8 findOwnerServer(struct dns_domain *domain, __u32 *ip) { 

    __u64 index = 0;

    for (size_t i = 0; i < 10 && (index < MAX_DNS_NAME_LENGTH) && (index + DNS_LIMIT <= MAX_DNS_NAME_LENGTH); i++)
    {
        if(domain->name[index] == 0)
            return ACCEPT;

        if (domain->domain_size - index <= DNS_LIMIT)    
        {
            struct a_record *nsrecord = bpf_map_lookup_elem(&cache_nsrecords, &domain->name[index]);

            if (nsrecord)
            {
                #ifdef DOMAIN
                    bpf_printk("[XDP] Subdomain: %s", &domain->name[index]);
                #endif

                #ifdef DOMAIN
                    bpf_printk("[XDP] Cache NS record try");
                #endif
                
                __u64 diff = getTTl(nsrecord->timestamp);

                #ifdef DOMAIN
                    bpf_printk("[XDP] TTL: %llu Current: %llu", nsrecord->ttl, diff);
                #endif

                if (nsrecord->ttl > diff && (nsrecord->ttl) - diff >  MINIMUM_TTL)
                {
                    *ip = nsrecord->ip;

                    #ifdef DOMAIN
                        bpf_printk("[XDP] Cache NS record hit");
                    #endif

                    return ACCEPT;
                }
                
                else
                    bpf_map_delete_elem(&cache_nsrecords, &domain->name[index]);
            }

        }

        index += domain->name[index] + 1;
    }

    return ACCEPT;
}

static __always_inline __u8 getAdditionalPointer(void *data, __u64 *offset, void *data_end, __u8 *pointer) {

    __u8 *content = data + *offset, count = 0;

    if (data + *offset + 2 > data_end)
        return DROP;

    *pointer = 0;

    if ((*content & 0xC0) == 0xC0)
        *pointer = (__u8) (bpf_ntohs(*((__u16 *) (content))) & 0x3FFF) - sizeof(struct dns_header);

    return ACCEPT;
}


static __always_inline __u8 getAdditional(void *data, __u64 *offset, void *data_end, struct a_record *record) {

    struct dns_header *header;    
    header = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

    record->status = (bpf_ntohs(header->flags) & 0x000F);

    __u8 *content = data + *offset, count = 0;

    for (size_t size = 0; size < 500; size++)
    {
        if (data + ++(*offset) + 3 > data_end)
            break;

        if ((bpf_ntohs(*((__u16 *) (content + size))) == NS_RECORD_TYPE || bpf_ntohs(*((__u16 *) (content + size))) == DS_TYPE) && bpf_ntohs(*((__u16 *) (content + size + 2))) == INTERNT_CLASS)
            count++;

        else if ((*(content + size) & 0xC0) == 0xC0) {

            if (count >= bpf_ntohs(header->name_servers))
            {   
                if (data + (*offset) + 5 > data_end)
                    return DROP;

                if (bpf_ntohs(*((__u16 *) (content + size + 2))) ^ A_RECORD_TYPE)
                    continue;

                if (bpf_ntohs(*((__u16 *) (content + size + 4))) ^ INTERNT_CLASS)
                    continue;
                
                if (data + (*offset) + 15 > data_end)
                    return DROP;

                record->ttl = bpf_ntohl(*((__u32 *) (content + size + 6)));
                
                record->ip = *((__u32 *) (content + size + 12));            
            
                return ACCEPT;
            }
        }
    }
    
    return ACCEPT_NO_ANSWER;
}

static __always_inline __u8 getAuthoritativePointer(void *data, __u64 *offset, void *data_end, __u8 *pointer, __u8 *off,  struct dns_domain *domain, struct dns_domain *subdomain)
{
    __builtin_memset(&subdomain->name, 0, MAX_DNS_NAME_LENGTH);

    __u8 *content = data + *offset;

    if (data + *offset + 1 > data_end)
        return DROP;

    if (*content == 0)
    {
        (*offset)++; *off++;

        return ACCEPT;
    }

    if (data + *offset + 2 > data_end)
        return DROP;

    if ((*(content) & 0xC0) == 0xC0)
    {
        *offset += 2;

        *pointer = (__u16) (bpf_ntohs(*(__u16 *) content) & 0x3FFF) - sizeof(struct dns_header);

        #ifdef DOMAIN
            bpf_printk("[XDP] Pointer: %u", *pointer);
        #endif

        for (size_t size = 0; size + *pointer < MAX_DNS_NAME_LENGTH; size++)
            subdomain->name[size] = domain->name[*pointer + size];

        *off += 2;

        return ACCEPT;
    }

    size_t size;

    #ifdef DOMAIN
        bpf_printk("[XDP] It's no pointer");
    #endif

    for (size = 0; size < MAX_DNS_NAME_LENGTH; size++)
    {
        if (data + ++(*offset) > data_end)
            return DROP;

        if (*(content + size) == 0)
        {
            (*off) += size + 1;

            return ACCEPT;
        }

        if ((*(content + size) & 0xC0) == 0xC0)
        {
            (*off) += size + 2;

            return ACCEPT;   
        }

        subdomain->name[size] = *(content + size);
    }

    return DROP;
}

static __always_inline __u8 getAuthoritative(void *data, __u64 *offset, void *data_end, struct dns_domain *autho, struct dns_domain *query, __u16 off) {

    __builtin_memset(autho->name, 0, MAX_DNS_NAME_LENGTH);

    __u64 newoff = *offset;

    __u8 *domain = data + *offset;
    
    *offset += query->domain_size + 5 + off;

    __u8 *type = data + *offset;

    *offset += 8;

    __u8 *content = data + *offset;

    *offset += 2;
    
    if (data + *(offset) > data_end)
        return DROP;

    autho->domain_size = (__u8) bpf_ntohs(*((__u16 *) (content)));

    if (autho->domain_size > MAX_DNS_NAME_LENGTH)
        return DROP;

    content += 2;

    if (type + 2 > data_end)
        return DROP;

    if (*((__u16 *) type) == SOA_RECORD_TYPE)
        return ACCEPT_NO_ANSWER;

    for (size_t size = 0; size < autho->domain_size; size++)
    {
        if (data + ++*(offset) > data_end)
            return ACCEPT_NO_ANSWER;

        if ((*(content + size) & 0xC0) == 0xC0)
        {
            if (data + (*offset) + 1 > data_end)
                return DROP;

            __u8 pointer = (bpf_ntohs(*((__u16 *) (content + size))) & 0x3FFF) - sizeof(struct dns_header);

            if (pointer >= query->domain_size)
                return DROP;

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

static __always_inline void incrementID(void *data)
{
    struct dns_header *header = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
    
    // Incrementa com overflow controlado
    header->id = bpf_htons((bpf_ntohs(header->id) + 1)); // Mantém o valor dentro de 16 bits
}

static __always_inline void decrementID(void *data)
{
    struct dns_header *header = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
    
    // Decrementa com underflow controlado
    header->id = bpf_htons((bpf_ntohs(header->id) - 1));
}

static __always_inline void hideInSourceIp(void *data, __u32 hidden)
{   
    struct iphdr *ipv4 = data + sizeof(struct ethhdr);

    ipv4->saddr = hidden;
}

static __always_inline __u8 hideInDestIp(void *data, void *data_end, __u32 hidden)
{   
    struct iphdr *ipv4 = data + sizeof(struct ethhdr);

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return DROP;

    ipv4->daddr = hidden;

    return ACCEPT;
}

static __always_inline __u32 getDestIp(void *data)
{   
    struct iphdr *ipv4 = data + sizeof(struct ethhdr);

    return ipv4->daddr;
}

static __always_inline __u8 getDNSStatus(void *data)
{   
    struct dns_header *header = (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr));

    return (bpf_ntohs(header->flags) & 0x000F);
}

static __always_inline void hideInDestPort(void *data, __u16 hidden)
{   
    struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

    udp->dest = hidden;
}

static __always_inline void hideInSourcePort(void *data, __u16 hidden)
{   
    struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

    udp->source = hidden;
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
            #ifdef FILTER
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
            #ifdef FILTER
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
            #ifdef FILTER
                bpf_printk("[XDP] It's to Port 53");
            #endif  
            break;
        case FROM_DNS_PORT:
        
            #ifdef FILTER
                bpf_printk("[XDP] It's from Port 53");
            #endif  

            bpf_tail_call(ctx, &tail_programs, DNS_PROCESS_RESPONSE_PROG);

            return XDP_DROP;
    }

    struct dns_query dnsquery;

    switch (isDNSQueryOrResponse(data, &offset_h, data_end, &dnsquery.id.id))
    {
        case DROP:
            return XDP_DROP;
        case PASS:
            return XDP_PASS;
        case QUERY_RETURN:
            #ifdef FILTER
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

            struct a_record *arecord = NULL;

            if (dnsquery.query.domain_size <= DNS_LIMIT)
                arecord = bpf_map_lookup_elem(&cache_arecords, dnsquery.query.name);

            if (arecord)
            {   
                #ifdef DOMAIN
                    bpf_printk("[XDP] Cache A record try");
                #endif
                
                __u64 diff = getTTl(arecord->timestamp);

                #ifdef DOMAIN
                    bpf_printk("[XDP] TTL: %llu Current: %llu", arecord->ttl, diff);
                #endif

                if (arecord->ttl > diff && (arecord->ttl) - diff >  MINIMUM_TTL)
                {
                    #ifdef DOMAIN
                        bpf_printk("[XDP] Cache A record  hit");
                    #endif

                    __s16 newsize = (data + offset_h - data_end);

                    if (arecord->ip ^ 0)
                        newsize += sizeof(struct dns_response);

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

                    switch (formatNetworkAcessLayer(data, &offset_h, data_end))
                    {
                        case DROP:
                            return XDP_DROP;
                        default:
                            #ifdef DOMAIN
                                bpf_printk("[XDP] Headers updated");
                            #endif  
                            break;
                    }

                    switch (swapInternetLayer(data, &offset_h, data_end))
                    {
                        case DROP:
                            return XDP_DROP;
                        default:
                            #ifdef DOMAIN
                                bpf_printk("[XDP] Headers updated");
                            #endif  
                            break;
                    }

                    switch (swapTransportLayer(data, &offset_h, data_end))
                    {
                        case DROP:
                            return XDP_DROP;
                        default:
                            #ifdef DOMAIN
                                bpf_printk("[XDP] Headers updated");
                            #endif  
                            break;
                    }

                    switch (createDNSAnswer(data, &offset_h, data_end, arecord->ip, arecord->ttl - diff, arecord->status, dnsquery.query.domain_size))
                    {
                        case DROP:
                            return XDP_DROP;
                        default:
                            #ifdef DOMAIN
                                bpf_printk("[XDP] Answer created");
                            #endif  
                            break;
                    }

                    return XDP_TX;
                }

                else
                    bpf_map_delete_elem(&cache_arecords, dnsquery.query.name);

            }

            struct query_owner owner;

            owner.ip_address = getSourceIp(data); dnsquery.id.port = getSourcePort(data); owner.rec = 0;

            if(bpf_map_update_elem(&recursive_queries, (struct rec_query_key *) &dnsquery, &owner, 0) < 0)
            {
                #ifdef ERROR
                    bpf_printk("[XDP] Recursive queries map error check cache");
                #endif  

                return XDP_PASS;
            }

            __u32 ip = recursive_server_ip;

            switch (findOwnerServer(&dnsquery.query, &ip))
            {
                case DROP:
                    return XDP_DROP;
                case PASS:
                    return XDP_PASS;
                default:
                    #ifdef DOMAIN
                        bpf_printk("[XDP] Authoritative server: %u", ip);
                    #endif
                    break;
            }

            offset_h = 0;

            switch (formatNetworkAcessLayer(data, &offset_h, data_end))
            {
                case DROP:
                    return XDP_DROP;
                default:
                    #ifdef DOMAIN
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

            switch(keepTransportLayer(data, &offset_h, data_end))
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
                bpf_printk("[XDP] Recursive Query created");
            #endif  

            return XDP_TX;

    default:
        break;
    }

    return XDP_PASS;
}

SEC("xdp")
int dns_process_response(struct xdp_md *ctx) {

    void *data_end = (void*) (long) ctx->data_end;
    void *data = (void*) (long) ctx->data;

    __u64 offset_h = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr); // Desclocamento d e bits para verificar as informações do pacote

    struct dns_query dnsquery; struct curr_query curr;

    __u8 query_response = isDNSQueryOrResponse(data, &offset_h, data_end, &dnsquery.id.id);

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

    __u8 back_to_last = 0, recursion_limit = 0;

    struct query_owner *powner = NULL; struct hop_query *lastdomain = NULL;

    powner = bpf_map_lookup_elem(&recursive_queries, (struct rec_query_key *) &dnsquery);

    if (powner)
    {
        powner->rec++;

        if (powner->rec >= 16)
            recursion_limit = 1;
    }

    else 
    {
        lastdomain = bpf_map_lookup_elem(&new_queries, (struct rec_query_key *) &dnsquery);

        if (lastdomain)
        {
            lastdomain->trash++;

            if (lastdomain->trash >= 16)
                recursion_limit = 1;
        }

        else
        {
            #ifdef DOMAIN
                bpf_printk("[XDP] It belongs to the OS");
            #endif

            return XDP_PASS;
        }
    }

    if (recursion_limit)
    {    
        if (hideInDestIp(data, data_end, 2) == DROP)
            return XDP_DROP;

        #ifdef DOMAIN
            bpf_printk("[XDP] Recursion Limit");
        #endif

        bpf_tail_call(ctx, &tail_programs, DNS_ERROR_PROG);

        return XDP_DROP;
    }

    if (query_response == RESPONSE_RETURN)
    {
        if (powner)
        {
            bpf_map_delete_elem(&recursive_queries, &dnsquery);

            offset_h = 0;

            switch (formatNetworkAcessLayer(data, &offset_h, data_end))
            {
                case DROP:
                    return XDP_DROP;
                default:
                    #ifdef DOMAIN
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

            switch(keepTransportLayer(data, &offset_h, data_end))
            {
                case DROP:
                    return XDP_DROP;
                default:
                    break;
            }

            switch(setDNSHeader(data, &offset_h, data_end))
            {
                case DROP:
                    return XDP_DROP;
                default:
                    break;
            }

            offset_h += dnsquery.query.domain_size + 5;
            
            struct a_record cache_record;

            switch (getDNSAnswer(data, &offset_h, data_end, &cache_record))
            {
                case DROP:
                    return XDP_DROP;
                case ACCEPT_NO_ANSWER:
                    #ifdef DOMAIN
                        bpf_printk("[XDP] No DNS answer");
                    #endif 
                    break;
                default:
                    if (dnsquery.query.domain_size <= DNS_LIMIT)
                    {
                        bpf_map_update_elem(&cache_arecords, dnsquery.query.name, &cache_record, 0);

                        #ifdef DOMAIN
                            bpf_printk("[XDP] A cache updated");
                        #endif  
                    }

                    break;
            }   

            #ifdef DOMAIN
                bpf_printk("[XDP] Recursive response returned");
            #endif

            return XDP_TX;
        }

        else if (lastdomain) 
        {
            if (bpf_map_update_elem(&curr_queries, &curr, &dnsquery, 0) < 0)
            {
                #ifdef DOMAIN
                    bpf_printk("[XDP] Error map 1");
                #endif

                #ifdef ERROR
                    bpf_printk("[XDP] Curr queries map error process");
                    bpf_printk("[XDP] Domain: %s", dnsquery.query.name);
                    bpf_printk("[XDP] ZERO");
                #endif  

                return XDP_PASS;
            }
            
            #ifdef DOMAIN
                bpf_printk("[XDP] A last response came");
            #endif

            bpf_tail_call(ctx, &tail_programs, DNS_BACK_TO_LAST_QUERY);

            return XDP_DROP;
        }

        else return XDP_PASS;        
    }
    

    if (dnsquery.query.domain_size <= DNS_LIMIT)
    {
        struct a_record *record = bpf_map_lookup_elem(&cache_arecords, dnsquery.query.name);

        if (record)
        {   
            #ifdef DOMAIN
                bpf_printk("[XDP] Cache A record try");
            #endif
            
            __u64 diff = getTTl(record->timestamp);

            #ifdef DOMAIN
                bpf_printk("[XDP] TTL: %llu Current: %llu", record->ttl, diff);
            #endif

            if (record->ttl > diff && (record->ttl) - diff >  MINIMUM_TTL)
            {
                #ifdef DOMAIN
                    bpf_printk("[XDP] Cache A record  hit");
                #endif
                
                if (powner)
                {
                    bpf_map_delete_elem(&recursive_queries, &dnsquery);

                    __s16 newsize = (data + offset_h - data_end);

                    if (record->ip ^ 0)
                        newsize += sizeof(struct dns_response);

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

                    switch (formatNetworkAcessLayer(data, &offset_h, data_end))
                    {
                        case DROP:
                            return XDP_DROP;
                        default:
                            #ifdef DOMAIN
                                bpf_printk("[XDP] Headers updated");
                            #endif  
                            break;
                    }

                    switch (returnToNetwork(data, &offset_h, data_end, powner->ip_address))
                    {
                        case DROP:
                            return XDP_DROP;
                        default:
                            #ifdef DOMAIN
                                bpf_printk("[XDP] Headers updated");
                            #endif  
                            break;
                    }

                    switch (keepTransportLayer(data, &offset_h, data_end))
                    {
                        case DROP:
                            return XDP_DROP;
                        default:
                            #ifdef DOMAIN
                                bpf_printk("[XDP] Headers updated");
                            #endif  
                            break;
                    }

                    switch (createDNSAnswer(data, &offset_h, data_end, record->ip, record->ttl - diff, record->status, dnsquery.query.domain_size))
                    {
                        case DROP:
                            return XDP_DROP;
                        default:
                            #ifdef DOMAIN
                                bpf_printk("[XDP] Answer created");
                            #endif  
                            break;
                    }

                    return XDP_TX;
                }

                else if (lastdomain)
                {
                    if (bpf_map_update_elem(&curr_queries, &curr, &dnsquery, 0) < 0)
                    {

                        #ifdef DOMAIN
                            bpf_printk("[XDP] Error map 2");
                        #endif

                        #ifdef ERROR
                            bpf_printk("[XDP] Curr queries map error process");
                            bpf_printk("[XDP] Domain: %s", dnsquery.query.name);
                            bpf_printk("[XDP] ZERO");
                        #endif  

                        return XDP_PASS;
                    }
                    
                    if (record->ip ^ 0) {

                        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
                            return XDP_DROP;
        
                        if (hideInDestIp(data, data_end, record->ip) == DROP)
                            return XDP_DROP;
        
                        #ifdef DOMAIN
                            bpf_printk("[XDP] A last response came");
                        #endif

                        bpf_tail_call(ctx, &tail_programs, DNS_BACK_TO_LAST_QUERY);

                        return XDP_DROP;
                    }
        
                    else
                    {
                        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
                            return XDP_DROP;
                        
                        if (hideInDestIp(data, data_end, 2) == DROP)
                            return XDP_DROP;
        
        
                        bpf_tail_call(ctx, &tail_programs, DNS_ERROR_PROG);
        
                        return XDP_DROP;
                    }
                }
            }

            else
                bpf_map_delete_elem(&cache_arecords, dnsquery.query.name);
        }

        record = bpf_map_lookup_elem(&cache_nsrecords, (struct rec_query_key *) dnsquery.query.name);

        if (record && record->ip != curr.ip)
        {   
            #ifdef DOMAIN
                bpf_printk("[XDP] Cache NS record try");
            #endif
            
            __u64 diff = getTTl(record->timestamp);

            #ifdef DOMAIN
                bpf_printk("[XDP] TTL: %llu Current: %llu", record->ttl, diff);
            #endif

            if (record->ttl > diff && (record->ttl) - diff >  MINIMUM_TTL)
            {
                #ifdef DOMAIN
                    bpf_printk("[XDP] Cache NS record hit");
                #endif

                __s16 newsize = (data + offset_h - data_end);

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

                switch (formatNetworkAcessLayer(data, &offset_h, data_end))
                {
                    case DROP:
                        return XDP_DROP;
                    default:
                        #ifdef DOMAIN
                            bpf_printk("[XDP] Headers updated");
                        #endif  
                        break;
                }

                switch (returnToNetwork(data, &offset_h, data_end, record->ip))
                {
                    case DROP:
                        return XDP_DROP;
                    default:
                        #ifdef DOMAIN
                            bpf_printk("[XDP] Headers updated");
                        #endif  
                        break;
                }

                switch (swapTransportLayer(data, &offset_h, data_end))
                {
                    case DROP:
                        return XDP_DROP;
                    default:
                        #ifdef DOMAIN
                            bpf_printk("[XDP] Headers updated");
                        #endif  
                        break;
                }

                switch(createDnsQuery(data, &offset_h, data_end))
                {
                    case DROP:
                        return XDP_DROP;
                    default:
                        break;
                }

                return XDP_TX;
            }

            else
                bpf_map_delete_elem(&cache_nsrecords, dnsquery.query.name);
        }
    }

    if (query_response != RESPONSE_RETURN)
    {
        __u8 *content = data + offset_h;

        if (data + offset_h + 1 <= data_end)
        {
            if (*content == 0)
            {
                #ifdef DOMAIN
                    bpf_printk("[XDP] Strange Packet");
                #endif

                if (bpf_map_update_elem(&curr_queries, &curr, &dnsquery, 0) < 0)
                {

                    #ifdef DOMAIN
                        bpf_printk("[XDP] Error map 3");
                    #endif

                    #ifdef ERROR
                        bpf_printk("[XDP] Curr queries map error process");
                        bpf_printk("[XDP] Domain: %s", dnsquery.query.name);
                        bpf_printk("[XDP] ZERO");
                    #endif  

                    return XDP_PASS;
                }

                if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
                    return XDP_DROP;

                if (hideInDestIp(data, data_end, 2) == DROP)
                    return XDP_DROP;

                if (bpf_map_update_elem(&curr_queries, &curr, &dnsquery, 0) < 0)
                {

                    #ifdef DOMAIN
                        bpf_printk("[XDP] Error map 4");
                    #endif
                    #ifdef ERROR
                        bpf_printk("[XDP] Curr queries map error process");
                        bpf_printk("[XDP] Domain: %s", dnsquery.query.name);
                        bpf_printk("[XDP] ZERO");
                    #endif  
            
                    return XDP_PASS;
                }
                
                bpf_tail_call(ctx, &tail_programs, DNS_ERROR_PROG);

                return XDP_DROP;
            }
        }      
    }

    if (query_response == QUERY_ADDITIONAL_RETURN)
    {
        __u8 pointer;

        switch (getAdditionalPointer(data, &offset_h, data_end, &pointer))
        {
            case DROP:
                return XDP_DROP;
            default:
                #ifdef DOMAIN
                    bpf_printk("[XDP] Additional Pointer: %d", pointer);
                #endif
                break;
        }

        if (hideInDestIp(data, data_end, pointer) == DROP)
            return XDP_DROP;

        if (bpf_map_update_elem(&curr_queries, &curr, &dnsquery, 0) < 0)
        {

            #ifdef DOMAIN
                bpf_printk("[XDP] Error map 5");
            #endif

            #ifdef ERROR
                bpf_printk("[XDP] Curr queries map error process");
                bpf_printk("[XDP] Domain: %s", dnsquery.query.name);
                bpf_printk("[XDP] ZERO");
            #endif  
    
            return XDP_PASS;
        }

        #ifdef DOMAIN
            bpf_printk("[XDP] Additional Query");
        #endif

        bpf_tail_call(ctx, &tail_programs, DNS_JUMP_QUERY_PROG);
        
        return XDP_DROP;
    }

    else if (query_response == QUERY_NAMESERVERS_RETURN)
    {
        if (powner)
            if (hideInDestIp(data, data_end, powner->rec) == DROP)
                return XDP_DROP;    

        if (lastdomain)
            if (hideInDestIp(data, data_end, lastdomain->trash) == DROP)
                return XDP_DROP;

        if (bpf_map_update_elem(&curr_queries, &curr, &dnsquery, 0) < 0)
        {

            #ifdef DOMAIN
                bpf_printk("[XDP] Error map 6");
            #endif

            #ifdef ERROR
                bpf_printk("[XDP] Curr queries map error process");
                bpf_printk("[XDP] Domain: %s", dnsquery.query.name);
                bpf_printk("[XDP] ZERO");
            #endif  
    
            return XDP_PASS;
        }

        #ifdef DOMAIN
            bpf_printk("[XDP] New query");
        #endif

        bpf_tail_call(ctx, &tail_programs, DNS_CHECK_SUBDOMAIN_PROG);

        return XDP_DROP;
    }

    #ifdef DOMAIN
        bpf_printk("[XDP] Nothing");
    #endif

    return XDP_PASS;
}

SEC("xdp")
int dns_jump_query(struct xdp_md *ctx) {

    #ifdef DOMAIN
        bpf_printk("[XDP] Dns hop");
    #endif

    void *data = (void*) (long) ctx->data;
    void *data_end = (void*) (long) ctx->data_end;
    
    __u64 offset_h = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header); // Desclocamento d e bits para verificar as informações do pacote

    if (data + offset_h > data_end)
        return XDP_DROP;

    __u8 pointer = getDestIp(data);

    struct curr_query curr;
    
    curr.ip = getSourceIp(data); curr.id.port = getDestPort(data); curr.id.id = getQueryId(data);

    struct dns_query *query = bpf_map_lookup_elem(&curr_queries, &curr);

    if (query)
    {
        if (query->query.domain_size >= MAX_DNS_NAME_LENGTH)
            return XDP_DROP;

        offset_h += query->query.domain_size + 5;

        if (data + offset_h > data_end)
            return XDP_DROP;

        struct a_record record;
        
        switch (getAdditional(data, &offset_h, data_end, &record))
        {
            case DROP:
                return XDP_DROP;
            case ACCEPT_NO_ANSWER:

                if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
                    return XDP_DROP;

                if (hideInDestIp(data, data_end, 5) == DROP)
                    return XDP_DROP;

                bpf_tail_call(ctx, &tail_programs, DNS_ERROR_PROG);

                return XDP_DROP;
            default:
                #ifdef DOMAIN
                    bpf_printk("[XDP] Additional IP: %u", record.ip);
                    bpf_printk("[XDP] Additional TTL: %u", record.ttl);
                    bpf_printk("[XDP] Additional Pointer: %u", pointer);
                #endif
                break;
        }
        
        bpf_map_delete_elem(&curr_queries, &curr);

        if ((query->query.domain_size - pointer < DNS_LIMIT) && (pointer + DNS_LIMIT <= MAX_DNS_NAME_LENGTH) && (pointer < MAX_DNS_NAME_LENGTH))
        {
            if (bpf_map_update_elem(&cache_nsrecords, &query->query.name[pointer], &record, 0) < 0)
            {
                #ifdef DOMAIN
                    bpf_printk("[XDP] NS Cache map error");
                #endif

                return XDP_PASS;
            }

            #ifdef DOMAIN
                bpf_printk("[XDP] NS Cache Updated");
            #endif
        }

        __s16 newsize = (__s16) ((data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header) + query->query.domain_size + 5) - data_end);

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

        switch (formatNetworkAcessLayer(data, &offset_h, data_end))
        {
            case DROP:
                return XDP_DROP;
            default:
                #ifdef DOMAIN
                    bpf_printk("[XDP] Headers updated");
                #endif  
                break;
        }

        switch(returnToNetwork(data, &offset_h, data_end, record.ip))
        {
            case DROP:
                return XDP_DROP;
            default:
                break;
        }

        switch (swapTransportLayer(data, &offset_h, data_end))
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

    return XDP_DROP;
}

SEC("xdp")
int dns_check_subdomain(struct xdp_md *ctx) {

    #ifdef DOMAIN
        bpf_printk("[XDP] DNS check subdomain");
    #endif 

    void *data = (void*) (long) ctx->data;
    void *data_end = (void*) (long) ctx->data_end;
    
    __u64 offset_h = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header); // Desclocamento d e bits para verificar as informações do pacote

    if (data + offset_h > data_end)
        return XDP_DROP;

    __u8 deep = getDestIp(data);

    #ifdef DEEP_2
        bpf_printk("Deep csd %d", deep);
    #endif 

    struct curr_query curr;
    
    curr.ip = getSourceIp(data); curr.id.port = getDestPort(data); curr.id.id = getQueryId(data);

    struct dns_query *query = bpf_map_lookup_elem(&curr_queries, &curr);

    if (query) {

        __u8 pointer = 0, off = 0;

        if (query->query.domain_size > MAX_DNS_NAME_LENGTH)
            return XDP_DROP;

        offset_h += query->query.domain_size + 5;

        if (data + offset_h > data_end)
            return XDP_DROP;

        struct dns_domain subdomain;

        switch (getAuthoritativePointer(data, &offset_h, data_end, &pointer, &off, &query->query, &subdomain))
        {
            case DROP:
                return XDP_DROP;            
            default:
                #ifdef DOMAIN
                    bpf_printk("[XDP] Subdomain %s", subdomain.name);
                #endif 
        
                break;
        }

        struct a_record *nsrecord = NULL;

        if (query->query.domain_size <= DNS_LIMIT)
            nsrecord = bpf_map_lookup_elem(&cache_nsrecords, query->query.name);

        if (!nsrecord)
        {   
            if (subdomain.domain_size <= DNS_LIMIT)
                nsrecord = bpf_map_lookup_elem(&cache_nsrecords, subdomain.name);
        }

        if (nsrecord && nsrecord->ip != curr.ip)
        {
            #ifdef DOMAIN
                bpf_printk("[XDP] Cache NS record try");
            #endif
            
            __u64 diff = getTTl(nsrecord->timestamp);

            #ifdef DOMAIN
                bpf_printk("[XDP] TTL: %llu Current: %llu", nsrecord->ttl, diff);
            #endif

            if (nsrecord->ttl > diff && (nsrecord->ttl) - diff >  MINIMUM_TTL)
            {
                bpf_map_delete_elem(&curr_queries, &curr);

                #ifdef DOMAIN
                    bpf_printk("[XDP] Cache NS record hit");
                #endif

                __s16 newsize = (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header) + query->query.domain_size + 5 - data_end);

                if (bpf_xdp_adjust_tail(ctx, (int) newsize) < 0)
                {
                    #ifdef DOMAIN
                        bpf_printk("[XDP] It was't possible to resize the packet");
                    #endif
                    
                    return XDP_DROP;
                }

                data = (void*) ctx->data;
                data_end = (void*) ctx->data_end;

                offset_h = 0;

                switch (formatNetworkAcessLayer(data, &offset_h, data_end))
                {
                    case DROP:
                        return XDP_DROP;
                    default:
                        #ifdef DOMAIN
                            bpf_printk("[XDP] Headers updated");
                        #endif  
                        break;
                }
                
                switch(returnToNetwork(data, &offset_h, data_end, nsrecord->ip))
                {
                    case DROP:
                        return XDP_DROP;
                    default:
                        break;
                }

                switch(swapTransportLayer(data, &offset_h, data_end))
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

                return XDP_TX;
            }
            
            else
                bpf_map_delete_elem(&cache_nsrecords, subdomain.name);
        }

        #ifdef DOMAIN
            bpf_printk("[XDP] off %d", off);
        #endif

        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end)
            return XDP_DROP;

        if (hideInDestIp(data, data_end, deep << 8 | pointer) == DROP)
            return XDP_DROP;
        
        hideInSourcePort(data, bpf_htons(off));

        bpf_tail_call(ctx, &tail_programs, DNS_CREATE_NEW_QUERY_PROG);
        
        return XDP_DROP;
    }

    return XDP_PASS;
}

SEC("xdp")
int dns_create_new_query(struct xdp_md *ctx) {

    #ifdef DOMAIN
        bpf_printk("[XDP] Dns new query");
    #endif

    void *data = (void*) (long) ctx->data;
    void *data_end = (void*) (long) ctx->data_end;
    
    __u64 offset_h = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header); // Desclocamento d e bits para verificar as informações do pacote

    if (data + offset_h > data_end)
        return XDP_DROP;

    __u16 off = getSourcePort(data); hideInSourcePort(data, bpf_htons(DNS_PORT));

    #ifdef DOMAIN
        bpf_printk("[XDP] off %d", off);
    #endif

    if (off > MAX_DNS_NAME_LENGTH)
        return XDP_DROP;
    
    struct curr_query curr;
    
    curr.ip = getSourceIp(data); curr.id.port = getDestPort(data); curr.id.id = getQueryId(data);

    struct dns_query *query = bpf_map_lookup_elem(&curr_queries, &curr);

    if (query) {

        struct dns_query dnsquery; 
        
        dnsquery.id = curr.id;

        switch(getAuthoritative(data, &offset_h, data_end, &dnsquery.query, &query->query, off))
        {
            case DROP:
                return XDP_DROP;
            case ACCEPT_NO_ANSWER:

                offset_h = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header) + query->query.domain_size + 5 + off - 2;

                struct a_record cache_record;

                switch (getDNSAnswer(data, &offset_h, data_end, &cache_record))
                {
                    case DROP:
                        return XDP_DROP;
                    case ACCEPT_NO_ANSWER:
                        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
                            return XDP_DROP;

                        if (hideInDestIp(data, data_end, 2) == DROP)
                            return XDP_DROP;

                        bpf_tail_call(ctx, &tail_programs, DNS_ERROR_PROG);

                        return XDP_DROP;

                        break;
                    default:
                        if (query->query.name <= DNS_LIMIT)
                        {
                            bpf_map_update_elem(&cache_arecords, query->query.name, &cache_record, 0);

                            #ifdef ERRO
                                bpf_printk("[XDP] A cache updated");
                            #endif   
                        }

                        if (hideInDestIp(data, data_end, 3) == DROP)
                            return XDP_DROP;

                        bpf_tail_call(ctx, &tail_programs, DNS_ERROR_PROG);
                        return XDP_DROP;
                        break;
                }
                
                return XDP_DROP;
            default:
                #ifdef DOMAIN
                    bpf_printk("[XDP] Authoritative %s", dnsquery.query.name);
		            bpf_printk("[XDP] Size: %u Type %u", dnsquery.query.domain_size, dnsquery.query.record_type);
                    bpf_printk("[XDP] Id: %u Port %u", dnsquery.id.id, dnsquery.id.port);
                #endif
                break;
        }

        bpf_map_delete_elem(&curr_queries, &curr);

        __u32 value = getDestIp(data);

        query->id.port =  value & 0xFF;
        dnsquery.id.id = bpf_htons((bpf_ntohs(dnsquery.id.id) + 1));

        incrementID(data); query->id.id = (value >> 8) & 0xFF;

	    if (bpf_map_update_elem(&new_queries, (struct rec_query_key *) &dnsquery, (struct hop_query *) query, 0) < 0)
        {
            #ifdef ERROR
                bpf_printk("[XDP] new query create new query");
            #endif

            return XDP_PASS;
        }

        __s16 newsize = (__s16) ((data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header) +  dnsquery.query.domain_size + 5) - data_end);

        if (bpf_xdp_adjust_tail(ctx, (int) newsize) < 0)
        {
            #ifdef DOMAIN
                bpf_printk("[XDP] It was't possible to resize the packet");
            #endif
            
            return XDP_DROP;
        }

        data = (void*) (long) ctx->data;
        data_end = (void*) (long) ctx->data_end;

        __u32 ip = recursive_server_ip;

        switch (findOwnerServer(&dnsquery.query, &ip))
        {
            case DROP:
                return XDP_DROP;
            case PASS:
                return XDP_PASS;
            default:
                #ifdef DOMAIN
                    bpf_printk("[XDP] Authoritative server: %u", ip);
                #endif
                break;
        }

        offset_h = 0;

        switch (formatNetworkAcessLayer(data, &offset_h, data_end))
        {
            case DROP:
                return XDP_DROP;
            default:
                #ifdef DOMAIN
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

        switch (swapTransportLayer(data, &offset_h, data_end))
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
            bpf_printk("[XDP] Recursive Query created");
        #endif  

        return XDP_TX;        
    }

    return XDP_PASS;
}

SEC("xdp")
int dns_back_to_last_query(struct xdp_md *ctx) {

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

        offset_h += query->query.domain_size + 5;

        if (data + offset_h > data_end)
            return XDP_DROP;

        struct hop_query *lastdomain = bpf_map_lookup_elem(&new_queries, query);

        if (lastdomain && lastdomain->query.domain_size <= MAX_DNS_NAME_LENGTH)
        {
            __u32 ip = getDestIp(data);

            __s16 newsize = (__s16) ((data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header)) - data_end) + lastdomain->query.domain_size + 5;

            if (ip == serverip)
            {
                struct a_record cache_record;
                cache_record.ip = 0;

                switch (getDNSAnswer(data, &offset_h, data_end, &cache_record))
                {
                    case DROP:
                        return XDP_DROP;
                    case ACCEPT_NO_ANSWER:
                        #ifdef DOMAIN
                            bpf_printk("[XDP] No DNS answer");
                        #endif 
                        break;
                    default:

                        if (query->query.domain_size <= DNS_LIMIT)
                        {
                            bpf_map_update_elem(&cache_arecords, query->query.name, &cache_record, 0);

                            #ifdef ERRO
                                bpf_printk("[XDP] A cache updated");
                            #endif   
                        }

                        #ifdef DOMAIN
                            bpf_printk("[XDP] A cache updated");
                        #endif   
                        break;
                }

                if (cache_record.ip == 0)
                {

                    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
                         return XDP_DROP;
                    
                    if (hideInDestIp(data, data_end, 3) == DROP)
                        return XDP_DROP;
                    
                    bpf_tail_call(ctx, &tail_programs, DNS_ERROR_PROG);
                }

                bpf_map_delete_elem(&curr_queries, &curr);

                bpf_map_delete_elem(&new_queries, query);

                __u8 pointer = lastdomain->pointer, deep = lastdomain->trash;
                
                #ifdef DEEP
                    bpf_printk("last %d", deep);
                #endif

                lastdomain->trash = bpf_htons((bpf_ntohs(curr.id.id) - 1));
                lastdomain->pointer = curr.id.port;

                struct hop_query *last_of_last = bpf_map_lookup_elem(&new_queries, lastdomain);

                if (last_of_last)
                {

                    last_of_last->trash = deep;

                    #ifdef DEEP
                        bpf_printk("curr %d", last_of_last->trash);
                    #endif
                }

                else {
                    
                    struct query_owner *powner = bpf_map_lookup_elem(&recursive_queries, (struct rec_query_key *) lastdomain);

                    if (powner)
                    {
                        powner->rec = deep;

                        #ifdef DEEP
                            bpf_printk("curr %d", powner->rec);
                        #endif
                    }                    
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

                switch (formatNetworkAcessLayer(data, &offset_h, data_end))
                {
                    case DROP:
                        return XDP_DROP;
                    default:
                        #ifdef DOMAIN
                            bpf_printk("[XDP] Headers updated");
                        #endif  
                        break;
                }
            
                switch(returnToNetwork(data, &offset_h, data_end, cache_record.ip))
                {
                    case DROP:
                        return XDP_DROP;
                    default:
                        break;
                }

                switch (swapTransportLayer(data, &offset_h, data_end))
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
                        decrementID(data);
                        break;
                }

                switch(writeQuery(data, &offset_h, data_end, &lastdomain->query))
                {
                    case DROP:
                        return XDP_DROP;
                    default:
                        break;
                }

                if (lastdomain->query.domain_size - pointer <= DNS_LIMIT &&  pointer + DNS_LIMIT <= MAX_DNS_NAME_LENGTH)
                {
                    if (bpf_map_update_elem(&cache_nsrecords, &lastdomain->query.name[pointer], &cache_record, 0) < 0)
                    {
                        #ifdef DOMAIN
                            bpf_printk("[XDP] NS Cache map error");
                        #endif

                        return XDP_PASS;
                    }

                    #ifdef DOMAIN
                        bpf_printk("[XDP] NS Cache Updated");
                    #endif
                }

                #ifdef DOMAIN
                    bpf_printk("[XDP] New back query created");
                #endif

                return XDP_TX;
            }

            else if (ip == 0)
            {

                if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
                    return XDP_DROP;

                if (hideInDestIp(data, data_end, 3) == DROP)
                    return XDP_DROP;

                bpf_tail_call(ctx, &tail_programs, DNS_ERROR_PROG);
            }

            else
            {
                bpf_map_delete_elem(&curr_queries, &curr);

                bpf_map_delete_elem(&new_queries, query);

                __u8 deep = lastdomain->trash;

                #ifdef DEEP
                    bpf_printk("last %d", deep);
                #endif

                lastdomain->trash = bpf_htons((bpf_ntohs(curr.id.id) - 1));
                lastdomain->pointer = curr.id.port;

                struct hop_query *last_of_last = bpf_map_lookup_elem(&new_queries, lastdomain);

                if (last_of_last)
                {

                    last_of_last->trash = deep;

                    #ifdef DEEP
                        bpf_printk("curr %d", last_of_last->trash);
                    #endif
                }

                else {
                    
                    struct query_owner *powner = bpf_map_lookup_elem(&recursive_queries, (struct rec_query_key *) lastdomain);

                    if (powner)
                    {
                        powner->rec = deep;

                        #ifdef DEEP
                            bpf_printk("curr %d", powner->rec);
                        #endif
                    }

                    
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

                switch (formatNetworkAcessLayer(data, &offset_h, data_end))
                {
                    case DROP:
                        return XDP_DROP;
                    default:
                        #ifdef DOMAIN
                            bpf_printk("[XDP] Headers updated");
                        #endif  
                        break;
                }

                switch (returnToNetwork(data, &offset_h, data_end, ip))
                {
                    case DROP:
                        return XDP_DROP;
                    default:
                        #ifdef DOMAIN
                            bpf_printk("[XDP] Headers updated");
                        #endif  
                        break;
                }

                switch (swapTransportLayer(data, &offset_h, data_end))
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
                        decrementID(data);
                        break;
                }

                switch(writeQuery(data, &offset_h, data_end, &lastdomain->query))
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
    }

    return XDP_PASS;
}

SEC("xdp")
int dns_error(struct xdp_md *ctx) {

    void *data_end = (void*) (long) ctx->data_end;
    void *data = (void*) (long) ctx->data;

    __u64 offset_h = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header); // Desclocamento d e bits para verificar as informações do pacote

    if (data + offset_h > data_end)
        return XDP_DROP;

    __u8 status = getDestIp(data);

    struct curr_query curr;
    
    curr.ip = getSourceIp(data); curr.id.port = getDestPort(data); curr.id.id = getQueryId(data);

    struct dns_query *query = bpf_map_lookup_elem(&curr_queries, &curr);

    if (query) {

        bpf_map_delete_elem(&curr_queries, &curr);

        struct hop_query *lastdomain = bpf_map_lookup_elem(&new_queries, (struct rec_query_key *) query);

        __u8 inter = 0;

        for (size_t i = 0; i < MAX_DNS_LABELS; i++)
        {
            if (lastdomain)
            {
                #ifdef DOMAIN
                    bpf_printk("[XDP] Cleaning domain: %s", lastdomain->query.name);
                #endif

                inter = 1;
                
                bpf_map_delete_elem(&new_queries, (struct rec_query_key *) query);

                __u16 id = bpf_htons((bpf_ntohs(query->id.id) - 1)), port = query->id.port;

                decrementID(data);

                query = lastdomain;
            
                query->id.id = id; query->id.port = port;
            }

            else
                break;

            lastdomain = bpf_map_lookup_elem(&new_queries, (struct rec_query_key *) query);
        }

        struct query_owner *powner = bpf_map_lookup_elem(&recursive_queries, (struct rec_query_key *) query);
        
        if (powner)
        {
            bpf_map_delete_elem(&recursive_queries, query);

            #ifdef DOMAIN
                bpf_printk("[XDP] Cleaning recursive query");
            #endif

            if (query->query.domain_size > MAX_DNS_NAME_LENGTH)
                return XDP_DROP;

            __s16 newsize = (__s16) ((data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header)) - data_end) + query->query.domain_size + 5;

            if (bpf_xdp_adjust_tail(ctx, (int) newsize) < 0)
            {
                #ifdef DOMAIN
                    bpf_printk("[XDP] It was't possible to resize the packet");
                #endif
                
                return XDP_DROP;
            }

            data_end = (void*) (long) ctx->data_end;
            data = (void*) (long) ctx->data;

            offset_h = 0;

            switch (formatNetworkAcessLayer(data, &offset_h, data_end))
            {
                case DROP:
                    return XDP_DROP;
                default:
                    #ifdef DOMAIN
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

            switch(keepTransportLayer(data, &offset_h, data_end))
            {
                case DROP:
                    return XDP_DROP;
                default:
                    break;
            }

            switch (createDNSAnswer(data, &offset_h, data_end, 0, 0, status, query->query.domain_size))
            {
                case DROP:
                    return XDP_DROP;
                default:
                    #ifdef DOMAIN
                        bpf_printk("[XDP] Answer created");
                    #endif  
                    break;
            }

            if (inter)
            {
                switch(writeQuery(data, &offset_h, data_end, &query->query))
                {
                    case DROP:
                        return XDP_DROP;
                    default:
                        break;
                }
            }

            return XDP_TX;
        }    
    }

    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
