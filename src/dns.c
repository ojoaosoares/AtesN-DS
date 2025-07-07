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

// #define DOMAIN

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  // 16MB buffer, você escolhe o tamanho
} ringbuf_send_packet SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_PROG_ARRAY); 
        __uint(max_entries, 8);                
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
        __uint(type, BPF_MAP_TYPE_LRU_HASH);
        __uint(max_entries, 2000000);
        __uint(key_size, sizeof(struct rec_query_key));
        __uint(value_size, sizeof(struct query_owner));

} recursive_queries SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_LRU_HASH);
        __uint(max_entries, 7000000);
        __uint(key_size, sizeof(struct rec_query_key));
        __uint(value_size, sizeof(struct hop_query));

} new_queries SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_LRU_HASH);
        __uint(max_entries, 400000);
        __uint(key_size, sizeof(char[MAX_DNS_NAME_LENGTH]));
        __uint(value_size, sizeof(struct a_record));

} cache_arecords SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_LRU_HASH);
        __uint(max_entries, 250000);
        __uint(key_size, sizeof(char[MAX_SUBDOMAIN_LENGTH]));
        __uint(value_size, sizeof(struct a_record));

} cache_nsrecords SEC(".maps");

__u32 recursive_server_ip;

__u32 serverip;

unsigned char gateway_mac[ETH_ALEN];

static __always_inline __u64 get_ttl(__u64 timestamp) {
    __u64 now = bpf_ktime_get_ns() / 1000000000;

    if (now >= timestamp)
        return 0;

    return timestamp - now;
}

__attribute__((__always_inline__))
static inline __u16 cal_udp_csum(struct iphdr *iph, struct udphdr *udph, void *data_end)
{
    __u32 csum_buffer = 0;
    __u16 *buf = (void *)udph;

    // Compute pseudo-header checksum
    csum_buffer += (__u16)iph->saddr;
    csum_buffer += (__u16)(iph->saddr >> 16);
    csum_buffer += (__u16)iph->daddr;
    csum_buffer += (__u16)(iph->daddr >> 16);
    csum_buffer += (__u16)iph->protocol << 8;
    csum_buffer += udph->len;

    // Compute checksum on udp header + payload
    for (int i = 0; i < MAX_UDP_SIZE; i += 2) 
    {
        if ((void *)(buf + 1) > data_end) 
        {
            break;
        }

        csum_buffer += *buf;
        buf++;
    }

    if ((void *)buf + 1 <= data_end) 
    {
        // In case payload is not 2 bytes aligned
        csum_buffer += *(__u8 *)buf;
    }

    __u16 csum = (__u16)csum_buffer + (__u16)(csum_buffer >> 16);
    csum = ~csum;

    return csum;
}

static __always_inline void compute_udp_checksum(void *data, void *data_end) {
    struct iphdr *ipv4 = data + sizeof(struct ethhdr);
    struct udphdr *udph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

    udph->check = cal_udp_csum(ipv4, udph, data_end);
}

static inline __u16 csum_fold_neg(__u32 csum)
{
    __u32 sum;
    sum = (csum >> 16) + (csum & 0xffff);
    sum += (sum >> 16);
    return ~((__u16)sum);
}

static inline __u32 csum_unfold(__u16 csum)
{
    return ~((uint32_t)csum);
}


static inline __u16 calculate_ip_checksum(struct iphdr *ip)
{
    ip->check = 0;
    __u32 csum = bpf_csum_diff(0, 0, (unsigned int *) ip, sizeof(struct iphdr), 0);
    
    return csum_fold_neg(csum);
}

static __always_inline __u8 is_ipv4(void *data, __u64 *offset, void *data_end)
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

static __always_inline __u8 is_valid_udp(void *data, __u64 *offset, void *data_end)
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
    
    if (ipv4->frag_off & IP_FRAGMENTED_MASK)
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

static __always_inline __u8 is_port_53(void *data, __u64 *offset, void *data_end)
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

static __always_inline __u8 is_dns_query_or_response(void *data, __u64 *offset, void *data_end, __u16 *id)
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

    // *id = header->id;
    *id = bpf_ntohs(header->id);

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

static __always_inline __u8 get_domain(void *data, __u64 *offset, void *data_end, struct dns_domain *query)
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

    if (bpf_ntohs(*((__u16 *) content)) ^ A_RECORD_TYPE)
    {
        #ifdef DOMAIN
            bpf_printk("[PASS] It's not a DNS query TYPE A");
        #endif

        return PASS;
    }

    content += 2;

    if (bpf_ntohs(*((__u16 *) content)) ^ DNS_CLASS_IN)
    {
        #ifdef DOMAIN
            bpf_printk("[PASS] It's not a DNS query class IN");
        #endif

        return PASS;
    }
    
    return ACCEPT;
}

static __always_inline __u16 get_query_id(void *data)
{
    struct dns_header *header = (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr));

    return bpf_ntohs(header->id);
    // return header->id;
}

static __always_inline __u16 get_source_port(void *data)
{
    struct udphdr *udp = (data + sizeof(struct ethhdr) + sizeof(struct iphdr));

    return bpf_ntohs(udp->source);
}

static __always_inline __u16 get_dest_port(void *data)
{
    struct udphdr *udp = (data + sizeof(struct ethhdr) + sizeof(struct iphdr));

    return bpf_ntohs(udp->dest);
}

static __always_inline __u32 get_source_ip(void *data)
{
    struct iphdr *ipv4 = (data + sizeof(struct ethhdr));

    return ipv4->saddr;
}

static __always_inline __u8 format_network_acess_layer(void *data, __u64 *offset, void *data_end)
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

static __always_inline __u8 swap_internet_layer(void *data, __u64 *offset, void *data_end)
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

    __u32 csum = csum_unfold(ipv4->check);

    __u32 new_ttl = 255;
    __u32 old_ttl = ipv4->ttl;
    ipv4->ttl = new_ttl;

    csum = bpf_csum_diff(&old_ttl, sizeof(__u32), &new_ttl, sizeof(__u32), csum);

    __u32 old_len = ipv4->tot_len;
    __u32 new_len = bpf_htons((data_end - data) - sizeof(struct ethhdr));
    ipv4->tot_len = new_len;

    csum = bpf_csum_diff(&old_len, sizeof(__u32), &new_len, sizeof(__u32), csum);

    ipv4->check = csum_fold_neg(csum);

    return ACCEPT;
}

static __always_inline __u8 keep_transport_layer(void *data, __u64 *offset, void *data_end)
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

static __always_inline __u8 swap_transport_layer(void *data, __u64 *offset, void *data_end)
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

static __always_inline __u8 set_dns_header(void *data, __u64 *offset, void *data_end) {

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

static __always_inline __u8 create_no_dns_answer(void *data, __u64 *offset, void *data_end, __u8 status)
{
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
    header->answer_count = bpf_htons(0);    
    header->flags = bpf_htons(flags);
        
    return ACCEPT;
}

static __always_inline __u8 create_dns_answer(void *data, __u64 *offset, void *data_end, __u32 ip, __u32 ttl, __u8 status, __u16 domain_size) {

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
    response->record_class = bpf_htons(DNS_CLASS_IN);
    response->record_type = bpf_htons(A_RECORD_TYPE);
    response->ttl = bpf_htonl(ttl);
    response->data_length = bpf_htons(sizeof(ip));
    response->ip = (ip);    

    return ACCEPT;
}

static __always_inline __u8 create_dns_query(void *data, __u64 *offset, void *data_end) {

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

static __always_inline __u8 return_to_network(void *data, __u64 *offset, void *data_end, __u32 ip_dest) {

    struct iphdr *ipv4 = data + *offset;

    *offset += sizeof(struct iphdr);

    if (data + *offset > data_end)
    {
        #ifdef DOMAIN
            bpf_printk("[DROP] Boundary exceded");
        #endif

        return DROP;
    }

    __u32 csum = csum_unfold(ipv4->check);

    __u32 old_saddr = ipv4->saddr;
    __u32 old_daddr = ipv4->daddr;

    ipv4->saddr = serverip;
    ipv4->daddr = ip_dest;

    csum = bpf_csum_diff(&old_saddr, sizeof(__u32), &ipv4->saddr, sizeof(__u32), csum);
    csum = bpf_csum_diff(&old_daddr, sizeof(__u32), &ipv4->daddr, sizeof(__u32), csum);

    __u32 new_ttl = 255;
    __u32 old_ttl = ipv4->ttl;
    ipv4->ttl = new_ttl;

    csum = bpf_csum_diff(&old_ttl, sizeof(__u32), &new_ttl, sizeof(__u32), csum);

    __u32 old_len = ipv4->tot_len;
    __u32 new_len = bpf_htons((data_end - data) - sizeof(struct ethhdr));
    ipv4->tot_len = new_len;

    csum = bpf_csum_diff(&old_len, sizeof(__u32), &new_len, sizeof(__u32), csum);

    ipv4->check = csum_fold_neg(csum);

    return ACCEPT;
}

static __always_inline __u8 get_dns_answer(void *data, __u64 *offset, void *data_end, struct a_record *record) {
    
    struct dns_header *header;
    
    header = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

    struct dns_response *response;

    response = data + *offset;

    if ((bpf_ntohs(header->flags) & 0x000F) == 2)
        return ACCEPT_NO_ANSWER;

    if ((bpf_ntohs(header->flags) & 0x000F) != 0 && (bpf_ntohs(header->flags) & 0x000F) != 3)
        return ACCEPT_ERROR;

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

        if (bpf_ntohs(response->record_class) ^ DNS_CLASS_IN)
            return ACCEPT_NO_ANSWER;

        if (bpf_ntohs(response->record_type) ^ A_RECORD_TYPE)
            return ACCEPT_NO_ANSWER;

        record->ip = response->ip;
        record->timestamp = (bpf_ktime_get_ns() / 1000000000) + bpf_ntohl(response->ttl);

        #ifdef DOMAIN
            bpf_printk("[XDP] Answer IP: %u", record->ip);
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

        if (bpf_ntohs(response->record_class) ^ DNS_CLASS_IN)
            return ACCEPT_NO_ANSWER;

        if(bpf_ntohs(response->record_type) ^ SOA_RECORD_TYPE)
            return ACCEPT_NO_ANSWER;

        record->ip = 0;
        record->timestamp = (bpf_ktime_get_ns() / 1000000000) + bpf_ntohl(response->ttl);
        
        return ACCEPT;  
    }
    
    return ACCEPT_NO_ANSWER;
}

static __always_inline __u8 find_owner_server(struct dns_domain *domain, __u32 *ip, __u8 *pointer) { 

    __u64 index = 0;

    for (size_t i = 0; i < MAX_LABELS_CHECK && (index < MAX_DNS_NAME_LENGTH) && (index + MAX_SUBDOMAIN_LENGTH <= MAX_DNS_NAME_LENGTH); i++)
    {
        if(domain->name[index] == 0)
        {
            *pointer = index;
            return 0;
        }

        if (domain->domain_size - index <= MAX_SUBDOMAIN_LENGTH)    
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
                
                __u64 diff = get_ttl(nsrecord->timestamp);

                #ifdef DOMAIN
                    bpf_printk("[XDP] Current: %llu", diff);
                #endif

                if (!nsrecord->ip)
                {
                    // if (diff > 3 || !nsrecord->timestamp)
                    // {
                    //     *pointer = domain->domain_size;
                    
                    //     return 1;
                    // }

                    // else 
                        continue;
                }

                if (diff >  MINIMUM_TTL)
                {
                    *ip = nsrecord->ip;

                    #ifdef DOMAIN
                        bpf_printk("[XDP] Cache NS record hit");
                    #endif

                    *pointer = index;

                    return 0;
                }

                else
                    bpf_map_delete_elem(&cache_nsrecords, &domain->name[index]);
            }
                
        }
        
        index += domain->name[index] + 1;
    }

    *pointer = index;
    
    return 0;
}

static __always_inline __u8 get_pointer(void *data, __u64 *offset, void *data_end, __u8 *pointer) {

    __u8 *content = data + *offset;

    if (data + *offset + 2 > data_end)
        return DROP;

    *pointer = 0;

    if ((*content & 0xC0) == 0xC0)
        *pointer = (__u8) (bpf_ntohs(*((__u16 *) (content))) & 0x3FFF) - sizeof(struct dns_header);

    return ACCEPT;
}


static __always_inline __u8 get_additional(void *data, __u64 *offset, void *data_end, struct a_record *record, __u8 domainsize, __u8 **remainder) {

    struct dns_header *header;    
    header = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

    record->ip = 0;

    __u8 *content = data + *offset;

    record->timestamp = (bpf_ktime_get_ns() / 1000000000);

    for (size_t size = 0; size < MAX_DNS_PAYLOAD - domainsize; size++) {
        
        if (content + size + 6 > data_end)
            break;

        if ((*((__u16 *)(content + size)) & 0xC0) == 0xC0 &&
            bpf_ntohs(*((__u16 *)(content + size + 2))) == A_RECORD_TYPE &&
            bpf_ntohs(*((__u16 *)(content + size + 4))) == DNS_CLASS_IN)
        {        
            if (content + size + 16 > data_end)
                return DROP;

            __u32 ttl = bpf_ntohl(*((__u32 *)(content + size + 6)));
            record->ip = *((__u32 *)(content + size + 12));            
            record->timestamp += ttl;

            *remainder = content + size + 16;
            return ACCEPT;           
        }
    }

    return ACCEPT_NO_ANSWER;
}

static __always_inline __u8 get_authoritative_pointer(void *data, __u64 *offset, void *data_end, __u8 *pointer, __u8 *off,  struct dns_domain *domain, struct dns_domain *subdomain)
{
    __builtin_memset(&subdomain->name, 0, MAX_DNS_NAME_LENGTH);

    __u8 *content = data + *offset;

    if (data + *offset + 1 > data_end)
        return DROP;

    if (*content == 0)
    {
        (*offset)++;

        return ACCEPT_JUST_POINTER;
    }

    if (data + *offset + 2 > data_end)
        return DROP;

    if ((*(content) & 0xC0) == 0xC0)
    {
        // subdomain->domain_size = 0;

        *offset += 2;

        *pointer = (__u16) (bpf_ntohs(*(__u16 *) content) & 0x3FFF) - sizeof(struct dns_header);

        #ifdef DOMAIN
            bpf_printk("[XDP] Pointer: %u", *pointer);
        #endif

        *off += 2;

        return ACCEPT_JUST_POINTER;
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

            subdomain->domain_size = size;

            return ACCEPT;
        }

        if ((*(content + size) & 0xC0) == 0xC0)
        {
            if (data + (*offset) + 1 > data_end)
                return DROP;

            *pointer = (__u16) (bpf_ntohs(*(__u16 *) (content + size)) & 0x3FFF) - sizeof(struct dns_header);

            (*off) += size + 2;

            // subdomain->domain_size = size;

            // return ACCEPT_JUST_POINTER;

            subdomain->domain_size = size + (domain->domain_size - *pointer);

            return ACCEPT;
        }

        subdomain->name[size] = *(content + size);
    }

    return DROP;
}

static __always_inline __u8 get_authoritative(void *data, __u64 *offset, void *data_end, struct dns_domain *autho, struct dns_domain *query, __u16 off) {

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

    if (((void *) type + 2) > data_end)
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

            if (size > MAX_DNS_NAME_LENGTH || pointer > MAX_DNS_NAME_LENGTH) 
                return DROP;

            autho->name[size] = query->name[pointer];

            for (size_t i = 0; pointer + i < MAX_DNS_NAME_LENGTH; i++)
            {
                if (data + ++newoff > data_end)
                    return DROP;

                *(domain) = query->name[pointer + i];

                if (*(domain++) == 0)
                    break;

                // autho->name[size + i] == query->name[pointer + i];
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

            *((__u16 *) domain) = bpf_htons(DNS_CLASS_IN);

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

    *((__u16 *) domain) = bpf_htons(DNS_CLASS_IN);

    return ACCEPT;
}

static __always_inline __u8 write_query(void *data, __u64 *offset, void *data_end, struct dns_domain *query) {

    __u8 *content = data + *offset;

    for (size_t i = 0; i < query->domain_size; i++)
    {
        if (data + ++*(offset) > data_end)
            return DROP;

        if (i > MAX_DNS_NAME_LENGTH)
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

    (* (__u16 *) content) = bpf_htons(A_RECORD_TYPE);

    content += 2;

    (* (__u16 *) content) = bpf_htons(DNS_CLASS_IN);

    return ACCEPT;
}

static __always_inline void modify_id(void *data, __u16 id)
{
    struct dns_header *header = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
    
    // Incrementa com overflow controlado
    // header->id = id;
    header->id = bpf_htons(id);
}

static __always_inline __u8 hide_in_dest_ip(void *data, void *data_end, __u32 hidden)
{   
    struct iphdr *ipv4 = data + sizeof(struct ethhdr);

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return DROP;

    ipv4->daddr = hidden;

    return ACCEPT;
}

static __always_inline __u32 get_dest_ip(void *data)
{   
    struct iphdr *ipv4 = data + sizeof(struct ethhdr);

    return ipv4->daddr;
}


static __always_inline void hide_in_source_port(void *data, __u16 hidden)
{   
    struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

    udp->source = hidden;
}

static __always_inline __u8 filter_dns(void *data, __u64 *offset,  void *data_end)
{
    switch (is_ipv4(data, offset, data_end))
    {
        case DROP:
            return DROP;
        case PASS:
            return PASS;
        default:
            #ifdef FILTER
                bpf_printk("[XDP] It's IPV4");
            #endif
            break;
    }

    switch (is_valid_udp(data, offset, data_end))
    {
        case DROP:
            return DROP;
        case PASS:
            return PASS;
        default:
            #ifdef FILTER
                bpf_printk("[XDP] It's UDP");
            #endif
            break;
    }

    switch (is_port_53(data, offset, data_end))
    {
        case DROP:
            return DROP;
        case PASS:
            return PASS;
        case TO_DNS_PORT:
            #ifdef FILTER
                bpf_printk("[XDP] It's to Port 53");
            #endif 
            break;
        case FROM_DNS_PORT:
            #ifdef FILTER
                bpf_printk("[XDP] It's from Port 53");
            #endif  

            return FROM_DNS_PORT;
            break;
    }

    return ACCEPT;
}

static __always_inline __u8 redirect_packet_keep(void *data, __u64 *offset, void *data_end, __u32 ip)
{
    if (format_network_acess_layer(data, offset, data_end) == DROP) 
        return DROP;
     
    if (return_to_network(data, offset, data_end, ip) == DROP)
        return DROP;

    if (keep_transport_layer(data, offset, data_end) == DROP)
        return DROP;
    
    return ACCEPT;
}

static __always_inline __u8 redirect_packet_swap(void *data, __u64 *offset, void *data_end, __u32 ip)
{
    if (format_network_acess_layer(data, offset, data_end) == DROP) 
        return DROP;
     
    if (return_to_network(data, offset, data_end, ip) == DROP)
        return DROP;

    if (swap_transport_layer(data, offset, data_end) == DROP)
        return DROP;
    
    return ACCEPT;
}

SEC("xdp")
int dns_filter(struct xdp_md *ctx) {

    void *data_end = (void*) (long) ctx->data_end;
    void *data = (void*) (long) ctx->data;

    __u64 offset_h; // Desclocamento d e bits para verificar as informações do pacote

    switch (filter_dns(data, &offset_h, data_end))
    {
        case DROP:
            return XDP_DROP;
        case PASS:
            return XDP_PASS;
        case FROM_DNS_PORT:
            bpf_tail_call(ctx, &tail_programs, DNS_RESPONSE_PROG);
            return XDP_DROP;
        default:
        #ifdef FILTER
            bpf_printk("[XDP] It's DNS protocol");
        #endif
        break;
    }

    struct dns_query dnsquery;

    __u8 query_response = is_dns_query_or_response(data, &offset_h, data_end, &dnsquery.id.id);

    switch (query_response)
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
            #ifdef DOMAIN
                bpf_printk("[XDP] It's a response");
            #endif
            return XDP_DROP;
            break;
    }
    
    dnsquery.id.port = get_source_port(data);

    switch (get_domain(data, &offset_h, data_end, &dnsquery.query))
    {
        case DROP:
            return XDP_DROP;
        case PASS:
            return XDP_PASS;
        default:
            #ifdef DOMAIN
                bpf_printk("[XDP] Domain: %s", dnsquery.query.name);
		        bpf_printk("[XDP] Size: %u", dnsquery.query.domain_size);
                bpf_printk("[XDP] Id: %u Port %u", dnsquery.id.id, dnsquery.id.port);
            #endif

            break;
    }

    struct a_record *arecord = bpf_map_lookup_elem(&cache_arecords, dnsquery.query.name);

    if (arecord)
    {   
        #ifdef DOMAIN
            bpf_printk("[XDP] Cache A record try");
        #endif
        
        __u64 diff = get_ttl(arecord->timestamp);

        #ifdef DOMAIN
            bpf_printk("[XDP] Current: %llu", diff);
        #endif

        if (diff >  MINIMUM_TTL)
        {
            #ifdef DOMAIN
                bpf_printk("[XDP] Cache A record  hit");
            #endif

            __s16 newsize = (data + offset_h - data_end);

            __u8 status = RCODE_NXDOMAIN;

            if (arecord->ip != 0)
            {
                newsize += sizeof(struct dns_response);
                status = RCODE_NOERROR;
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

            if (format_network_acess_layer(data, &offset_h, data_end) == DROP)
                return XDP_DROP;
        
            if (swap_internet_layer(data, &offset_h, data_end) == DROP)
                return XDP_DROP;

            if (swap_transport_layer(data, &offset_h, data_end) == DROP)
                return XDP_DROP;

            if (create_dns_answer(data, &offset_h, data_end, arecord->ip, diff, status, dnsquery.query.domain_size) == DROP)
                return XDP_DROP;

            bpf_tail_call(ctx, &tail_programs, DNS_UDP_CSUM_PROG);

            return XDP_DROP;
        }

        else
            bpf_map_delete_elem(&cache_arecords, dnsquery.query.name);

    }

    __u32 ip = recursive_server_ip;
    __u8 pointer = dnsquery.query.domain_size;

    if (find_owner_server(&dnsquery.query, &ip, &pointer))
        return XDP_PASS;
    
    #ifdef DOMAIN
        bpf_printk("[XDP] Authoritative server: %u", ip);
    #endif
    
    struct query_owner owner = {
        .ip = get_source_ip(data),
        .rec = 0,
        .not_cache = 0,
        .curr_pointer = pointer
    };

    if(bpf_map_update_elem(&recursive_queries, (struct dns_query_key *) &dnsquery, &owner, BPF_ANY) < 0)
    {
        #ifdef ERROR
            bpf_printk("[XDP] Recursive queries map error check cache");
            bpf_printk("[XDP] Domain: %s", dnsquery.query.name);
        #endif  

        return XDP_PASS;
    }

    offset_h = 0;

    if (redirect_packet_keep(data, &offset_h, data_end, ip) == DROP)
        return XDP_DROP;

    if (create_dns_query(data, &offset_h, data_end) == DROP)
        return XDP_DROP;

    #ifdef DOMAIN
        bpf_printk("[XDP] Recursive Query created");
    #endif  

    bpf_tail_call(ctx, &tail_programs, DNS_UDP_CSUM_PROG);

    return XDP_DROP;
}


SEC("xdp") 
int dns_response(struct xdp_md *ctx)
{
    void *data = (void*) (long) ctx->data;
    void *data_end = (void*) (long) ctx->data_end;
    
    __u64 offset_h = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

    struct dns_query dnsquery;

    __u8 query_response = is_dns_query_or_response(data, &offset_h, data_end, &dnsquery.id.id);

    switch (query_response)
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
            #ifdef DOMAIN
                bpf_printk("[XDP] It's a response");
            #endif
            break;
    }

    struct curr_query curr = {
        .id.id = dnsquery.id.id,
        .id.port = get_dest_port(data),
        .ip = get_source_ip(data),
    };

    dnsquery.id.port = curr.id.port;

    switch (get_domain(data, &offset_h, data_end, &dnsquery.query))
    {
        case DROP:
            return XDP_DROP;
        case PASS:
            return XDP_PASS;
        default:
            #ifdef DOMAIN
                bpf_printk("[XDP] Domain: %s", dnsquery.query.name);
		        bpf_printk("[XDP] Size: %u", dnsquery.query.domain_size);
                bpf_printk("[XDP] Id: %u Port %u", dnsquery.id.id, dnsquery.id.port);
            #endif

            break;
    }

    __u8 recursion_limit = 0, aprove = 0, pointer = dnsquery.query.domain_size;

    struct query_owner *powner = NULL; struct hop_query *lastdomain = NULL;

    powner = bpf_map_lookup_elem(&recursive_queries, (struct rec_query_key *) &dnsquery);

    if (powner)
    {
        powner->rec++;

        if (powner->rec >= 16)
            recursion_limit = 1;

        if (powner->not_cache)
        {
            powner->not_cache = 0;
            aprove = 1;
            pointer = powner->curr_pointer;
        }
    }

    else 
    {
        lastdomain = bpf_map_lookup_elem(&new_queries, (struct rec_query_key *) &dnsquery);

        if (lastdomain)
        {

            __u8 rec = ++lastdomain->recursion_state;

            if (rec >= 16)
                recursion_limit = 1;

            if (lastdomain->recursion_state & (1 << 8)) 
            {
                lastdomain->recursion_state &= ~(1 << 8);
                aprove = 1;
                pointer = (lastdomain->pointer >> 8);
            }
        }

        else
        {
            #ifdef DOMAIN
                bpf_printk("[XDP] It belongs to the OS");
            #endif

            return XDP_PASS;
        }
    }

    if (aprove)
    {
        if ((dnsquery.query.domain_size - pointer <= MAX_SUBDOMAIN_LENGTH) && (pointer + MAX_SUBDOMAIN_LENGTH <= MAX_DNS_NAME_LENGTH) && (pointer < MAX_DNS_NAME_LENGTH))
        {
            struct a_record *record_aprove = bpf_map_lookup_elem(&cache_nsrecords, (struct rec_query_key *) &dnsquery.query.name[pointer]);

            if (record_aprove)
            {
                #ifdef DOMAIN
                    bpf_printk("[XDP] Cache aproved");
                #endif            

                record_aprove->ip = curr.ip;    
            }
        }
    }

    if (recursion_limit && query_response != RESPONSE_RETURN)
    {    
        if (hide_in_dest_ip(data, data_end, RCODE_SERVERFAIL) == DROP)
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

            if (redirect_packet_keep(data, &offset_h, data_end, powner->ip) == DROP)
                return XDP_DROP;

            if (set_dns_header(data, &offset_h, data_end) == DROP)
                return XDP_DROP;
            

            offset_h += dnsquery.query.domain_size + 5;
            
            struct a_record cache_record;
            cache_record.ip = 0;
            cache_record.timestamp = 0;

            if (get_dns_answer(data, &offset_h, data_end, &cache_record) == DROP)
                return XDP_DROP;

            if (cache_record.timestamp)
            {
                bpf_map_update_elem(&cache_arecords, dnsquery.query.name, &cache_record, BPF_ANY);

                #ifdef DOMAIN
                    bpf_printk("[XDP] A cache updated");
                #endif  
            }

            #ifdef DOMAIN
                bpf_printk("[XDP] Recursive response returned");
            #endif

            bpf_tail_call(ctx, &tail_programs, DNS_UDP_CSUM_PROG);

            return XDP_DROP;
        }

        else if (lastdomain) 
        {
            if (bpf_map_update_elem(&curr_queries, &curr, &dnsquery, BPF_ANY) < 0)
            {
                #ifdef SO
                    bpf_printk("[XDP] Curr queries map error process/response return");
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
    
    struct a_record *record = NULL;

    if (powner)
    {
        record = bpf_map_lookup_elem(&cache_arecords, dnsquery.query.name);

        if (record)
        {   
            #ifdef DOMAIN
                bpf_printk("[XDP] Cache A record try");
            #endif
            
            __u64 diff = get_ttl(record->timestamp);

            #ifdef DOMAIN
                bpf_printk("[XDP] Current: %llu", diff);
            #endif

            if (diff >  MINIMUM_TTL)
            {
                #ifdef DOMAIN
                    bpf_printk("[XDP] Cache A record  hit");
                #endif
                
                bpf_map_delete_elem(&recursive_queries, &dnsquery);

                __s16 newsize = (data + offset_h - data_end);

                __u8 status = RCODE_NXDOMAIN;

                if (record->ip != 0)
                {
                    newsize += sizeof(struct dns_response); status = RCODE_NOERROR;
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

                if (redirect_packet_keep(data, &offset_h, data_end, powner->ip) == DROP)
                    return XDP_DROP;

                if (create_dns_answer(data, &offset_h, data_end, record->ip, diff, status, dnsquery.query.domain_size) == DROP)
                    return XDP_DROP;

                bpf_tail_call(ctx, &tail_programs, DNS_UDP_CSUM_PROG);

                return XDP_DROP;
            }

            else
                bpf_map_delete_elem(&cache_arecords, dnsquery.query.name);
        }
    
        record = bpf_map_lookup_elem(&cache_nsrecords, (struct rec_query_key *) dnsquery.query.name);

        if (record && record->ip && record->ip != curr.ip)
        {   
            #ifdef DOMAIN
                bpf_printk("[XDP] Cache NS record try");
            #endif
            
            __u64 diff = get_ttl(record->timestamp);

            #ifdef DOMAIN
                bpf_printk("[XDP] Current: %llu", diff);
            #endif

            if (diff >  MINIMUM_TTL)
            {
                #ifdef DOMAIN
                    bpf_printk("[XDP] Cache NS record hit");
                #endif

                if (powner)
                    powner->curr_pointer = 0;
                
                else if (lastdomain)
                    lastdomain->pointer &= 0x00FF;
                
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

                if (redirect_packet_swap(data, &offset_h, data_end, record->ip) == DROP)
                    return XDP_DROP;

                if (create_dns_query(data, &offset_h, data_end) == DROP)
                    return XDP_DROP;

                bpf_tail_call(ctx, &tail_programs, DNS_UDP_CSUM_PROG);

                return XDP_DROP;
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

                if (bpf_map_update_elem(&curr_queries, &curr, &dnsquery, BPF_ANY) < 0)
                {

                    #ifdef ERROR
                        bpf_printk("[XDP] Curr queries map error/error");
                    #endif  

                    return XDP_PASS;
                }

                if (hide_in_dest_ip(data, data_end, RCODE_SERVERFAIL) == DROP)
                    return XDP_DROP;

                bpf_tail_call(ctx, &tail_programs, DNS_ERROR_PROG);

                return XDP_DROP;
            }
        }      
    }

    if (query_response == QUERY_ADDITIONAL_RETURN)
    {
        __u8 pointer;

        switch (get_pointer(data, &offset_h, data_end, &pointer))
        {
            case DROP:
                return XDP_DROP;
            default:
                #ifdef DOMAIN
                    bpf_printk("[XDP] Additional Pointer: %d", pointer);
                #endif
                break;
        }

        if (hide_in_dest_ip(data, data_end, pointer) == DROP)
            return XDP_DROP;

        if (bpf_map_update_elem(&curr_queries, &curr, &dnsquery, BPF_ANY) < 0)
        {
            #ifdef ERROR
                bpf_printk("[XDP] Curr queries map error/additional");
            #endif  
    
            return XDP_PASS;
        }

        #ifdef DOMAIN
            bpf_printk("[XDP] Additional Query");
        #endif

        if (powner)
        {
            powner->not_cache = 1;
            powner->curr_pointer = pointer;
        }

        else if (lastdomain)
        {
            lastdomain->recursion_state |= (1 << 8);
            lastdomain->pointer &= 0x00FF;
            lastdomain->pointer |= (pointer << 8);
        }

        bpf_tail_call(ctx, &tail_programs, DNS_JUMP_QUERY_PROG);
        
        return XDP_DROP;
    }

    else if (query_response == QUERY_NAMESERVERS_RETURN)
    {
        __u8 pointer;

        switch (get_pointer(data, &offset_h, data_end, &pointer))
        {
            case DROP:
                return XDP_DROP;
            default:
                #ifdef DOMAIN
                    bpf_printk("[XDP] Additional Pointer: %d", pointer);
                #endif
                break;
        }

        if (powner)
        {
            if (hide_in_dest_ip(data, data_end, powner->rec) == DROP)
                return XDP_DROP;    

            powner->curr_pointer = pointer;
        }

        else if (lastdomain)
        {
            if (hide_in_dest_ip(data, data_end, lastdomain->recursion_state) == DROP)
                return XDP_DROP;

            lastdomain->pointer &= 0x00FF;
            lastdomain->pointer |= (pointer << 8);
        }

        if (bpf_map_update_elem(&curr_queries, &curr, &dnsquery, BPF_ANY) < 0)
        {
            #ifdef ERROR
                bpf_printk("[XDP] Curr queries map error process/nameservers");
            #endif  
    
            return XDP_PASS;
        }

        #ifdef DOMAIN
            bpf_printk("[XDP] New query");
        #endif

        bpf_tail_call(ctx, &tail_programs, DNS_CHECK_SUBDOMAIN_PROG);

        return XDP_DROP;
    }

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

    __u8 pointer = get_dest_ip(data);
    hide_in_dest_ip(data, data_end, serverip);

    struct curr_query curr = {
        .id.id = get_query_id(data),
        .id.port = get_dest_port(data),
        .ip = get_source_ip(data)
    };

    struct dns_query *query = bpf_map_lookup_elem(&curr_queries, &curr);

    if (query)
    {
        if (query->query.domain_size >= MAX_DNS_NAME_LENGTH)
            return XDP_DROP;

        offset_h += query->query.domain_size + 5;

        if (data + offset_h > data_end)
            return XDP_DROP;

        struct a_record record;
        
        __u8 *remainder;
        
        switch (get_additional(data, &offset_h, data_end, &record, query->query.domain_size, &remainder))
        {
            case DROP:
                return XDP_DROP;
            case ACCEPT_NO_ANSWER:

                if (hide_in_dest_ip(data, data_end, RCODE_SERVERFAIL) == DROP)
                    return XDP_DROP;

                bpf_tail_call(ctx, &tail_programs, DNS_ERROR_PROG);

                return XDP_DROP;
            default:
                #ifdef DOMAIN
                    bpf_printk("[XDP] Additional IP: %u", record.ip);
                    bpf_printk("[XDP] Additional Pointer: %u", pointer);
                #endif
                break;
        }
         
        __u16 remainder_off = ((long) ((void*) remainder) - (long) data);

        hide_in_source_port(data, bpf_htons(remainder_off)); 
        hide_in_dest_ip(data, data_end, record.ip);

        if ((query->query.domain_size - pointer <= MAX_SUBDOMAIN_LENGTH) && (pointer + MAX_SUBDOMAIN_LENGTH <= MAX_DNS_NAME_LENGTH))
        {
            record.ip = 0;

            if (bpf_map_update_elem(&cache_nsrecords, &query->query.name[pointer], &record, BPF_ANY) < 0)
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

        bpf_tail_call(ctx, &tail_programs, DNS_SEND_EVENT_PROG);
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

    __u8 deep = get_dest_ip(data);
    hide_in_dest_ip(data, data_end, serverip);

    struct curr_query curr = {
        .id.id = get_query_id(data),
        .id.port = get_dest_port(data),
        .ip = get_source_ip(data)
    };

    struct dns_query *query = bpf_map_lookup_elem(&curr_queries, &curr);

    if (query) {

        __u8 pointer = 0, off = 0;

        if (query->query.domain_size > MAX_DNS_NAME_LENGTH)
            return XDP_DROP;

        offset_h += query->query.domain_size + 5;

        if (data + offset_h > data_end)
            return XDP_DROP;

        struct dns_domain subdomain;

        struct a_record *nsrecord = NULL;

        switch (get_authoritative_pointer(data, &offset_h, data_end, &pointer, &off, &query->query, &subdomain))
        {
            case DROP:
                return XDP_DROP;   
            case ACCEPT:
                #ifdef DOMAIN
                    bpf_printk("[XDP] Subdomain %s", subdomain.name);
                #endif 

                if (subdomain.domain_size <= MAX_SUBDOMAIN_LENGTH)
                    nsrecord = bpf_map_lookup_elem(&cache_nsrecords, subdomain.name);

                break;
            case ACCEPT_JUST_POINTER:
                #ifdef DOMAIN
                    bpf_printk("[XDP] Subpointer %d", pointer);
                #endif 

                // if (subdomain.domain_size)
                // {

                //     for (size_t i = subdomain.domain_size, j = pointer; i < MAX_DNS_NAME_LENGTH && j < query->query.domain_size; i++, j++)
                //         subdomain.name[i] = query->query.name[j];

                    
                //     if ((query->query.domain_size - pointer <= MAX_SUBDOMAIN_LENGTH) && (pointer + MAX_SUBDOMAIN_LENGTH <= MAX_DNS_NAME_LENGTH) && (pointer < MAX_DNS_NAME_LENGTH))
                //         nsrecord = bpf_map_lookup_elem(&cache_nsrecords, query->query.name);            
                // }

                if ((query->query.domain_size - pointer <= MAX_SUBDOMAIN_LENGTH) && (pointer + MAX_SUBDOMAIN_LENGTH <= MAX_DNS_NAME_LENGTH) && (pointer < MAX_DNS_NAME_LENGTH))
                    nsrecord = bpf_map_lookup_elem(&cache_nsrecords, query->query.name);            

            default:        
                break;
        }

        if (nsrecord && nsrecord->ip && nsrecord->ip != curr.ip)
        {
            #ifdef DOMAIN
                bpf_printk("[XDP] Cache NS record try");
            #endif
            
            __u64 diff = get_ttl(nsrecord->timestamp);

            #ifdef DOMAIN
                bpf_printk("[XDP] Current: %llu", diff);
            #endif

            if (diff >  MINIMUM_TTL)
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

                data = (void*) (long) ctx->data;
                data_end = (void*) (long) ctx->data_end;

                offset_h = 0;

                if (format_network_acess_layer(data, &offset_h, data_end) == DROP)
                    return XDP_DROP;
                
                if (return_to_network(data, &offset_h, data_end, nsrecord->ip) == DROP)
                    return XDP_DROP;

                if (swap_transport_layer(data, &offset_h, data_end) == DROP)
                    return XDP_DROP;

                if (create_dns_query(data, &offset_h, data_end) == DROP)
                    return XDP_DROP;

                #ifdef DOMAIN
                    bpf_printk("[XDP] Query goes by check_subdomain");
                #endif  

                bpf_tail_call(ctx, &tail_programs, DNS_UDP_CSUM_PROG);

                return XDP_DROP;
            }
            
            else
                bpf_map_delete_elem(&cache_nsrecords, subdomain.name);
        }

        #ifdef DOMAIN
            bpf_printk("[XDP] off %d", off);
        #endif

        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end)
            return XDP_DROP;

        if (hide_in_dest_ip(data, data_end, deep << 8 | pointer) == DROP)
            return XDP_DROP;
        
        hide_in_source_port(data, bpf_htons(off));

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

    __u16 off = get_source_port(data); hide_in_source_port(data, bpf_htons(DNS_PORT));

    #ifdef DOMAIN
        bpf_printk("[XDP] off %d", off);
    #endif

    if (off > MAX_DNS_NAME_LENGTH)
        return XDP_DROP;

    struct curr_query curr = {
        .id.id = get_query_id(data),
        .id.port = get_dest_port(data),
        .ip = get_source_ip(data)
    };
    
    struct dns_query *query = bpf_map_lookup_elem(&curr_queries, &curr);

    if (query) {

        struct dns_query dnsquery; 
        
        dnsquery.id.port = curr.id.port;
        dnsquery.id.id = curr.id.id;

        switch(get_authoritative(data, &offset_h, data_end, &dnsquery.query, &query->query, off))
        {
            case DROP:
                return XDP_DROP;
            case ACCEPT_NO_ANSWER:

                offset_h = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header) + query->query.domain_size + 5 + off - 2;

                struct a_record cache_record;

                switch (get_dns_answer(data, &offset_h, data_end, &cache_record))
                {
                    case DROP:
                        return XDP_DROP;

                    case ACCEPT_ERROR:
                    case ACCEPT_NO_ANSWER:

                        if (hide_in_dest_ip(data, data_end, RCODE_SERVERFAIL) == DROP)
                            return XDP_DROP;

                        bpf_tail_call(ctx, &tail_programs, DNS_ERROR_PROG);

                        return XDP_DROP;

                        break;
                    default:

                        bpf_map_update_elem(&cache_arecords, query->query.name, &cache_record, BPF_ANY);

                        if (hide_in_dest_ip(data, data_end, RCODE_NXDOMAIN) == DROP)
                            return XDP_DROP;

                        bpf_tail_call(ctx, &tail_programs, DNS_ERROR_PROG);
                        
                        return XDP_DROP;

                        break;
                }
                
                return XDP_DROP;                
            default:
                #ifdef DOMAIN
                    bpf_printk("[XDP] Authoritative %s", dnsquery.query.name);
		            bpf_printk("[XDP] Size: %u", dnsquery.query.domain_size);
                    bpf_printk("[XDP] Id: %u Port %u", dnsquery.id.id, dnsquery.id.port);
                #endif
                break;
        }

        bpf_map_delete_elem(&curr_queries, &curr);

        __u32 ip = recursive_server_ip; __u8 pointer;

        find_owner_server(&dnsquery.query, &ip, &pointer);
        
        #ifdef DOMAIN
            bpf_printk("[XDP] Authoritative server: %u", ip);
        #endif

        __u32 value = get_dest_ip(data);
        hide_in_dest_ip(data, data_end, serverip);

        #ifdef DOMAIN
            bpf_printk("[XDP] Last %s", query->query.name);
            bpf_printk("[XDP] New %s", dnsquery.query.name);
            
        #endif

        dnsquery.id.id += 1;

        modify_id(data, dnsquery.id.id); query->id.id = (value >> 8) & 0xFF;

        query->id.port = ((pointer & 0xFF) << 8) | (value & 0xFF);

	    if (bpf_map_update_elem(&new_queries, (struct rec_query_key *) &dnsquery, (struct hop_query *) query, BPF_ANY) < 0)
        {
            #ifdef ERROR
                bpf_printk("[XDP] new query map error");
                bpf_printk("[XDP] Domain %s", dnsquery.query.name);
            #endif

            return XDP_DROP;
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

        offset_h = 0;

        if (redirect_packet_swap(data, &offset_h, data_end, ip) == DROP)
            return XDP_DROP;

        if (create_dns_query(data, &offset_h, data_end) == DROP)
            return XDP_DROP;
        
        #ifdef DOMAIN
            bpf_printk("[XDP] Recursive Query created");
        #endif  

        bpf_tail_call(ctx, &tail_programs, DNS_UDP_CSUM_PROG);

        return XDP_DROP;
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

    struct curr_query curr = {
        .id.id = get_query_id(data),
        .id.port = get_dest_port(data),
        .ip = get_source_ip(data)
    };

    struct dns_query *query = bpf_map_lookup_elem(&curr_queries, &curr);

    if (query) {

        offset_h += query->query.domain_size + 5;

        if (data + offset_h > data_end)
            return XDP_DROP;

        struct hop_query *lastdomain = bpf_map_lookup_elem(&new_queries, query);

        if (lastdomain && lastdomain->query.domain_size <= MAX_DNS_NAME_LENGTH)
        {
            __u32 ip = get_dest_ip(data);
            hide_in_dest_ip(data, data_end, serverip);

            __s16 newsize = (__s16) ((data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header)) - data_end) + lastdomain->query.domain_size + 5;

            if (ip == serverip)
            {
                struct a_record cache_record;
                cache_record.ip = 0;
                cache_record.timestamp = 0;

                if (get_dns_answer(data, &offset_h, data_end, &cache_record) == DROP)
                    return XDP_DROP;
            
                if (cache_record.timestamp)
                {
                    bpf_map_update_elem(&cache_arecords, query->query.name, &cache_record, BPF_ANY);

                    #ifdef ERRO
                        bpf_printk("[XDP] A cache updated");
                    #endif   
                }

                if (cache_record.ip == 0)
                {   
                    if (hide_in_dest_ip(data, data_end, RCODE_NXDOMAIN) == DROP)
                        return XDP_DROP;
                    
                    bpf_tail_call(ctx, &tail_programs, DNS_ERROR_PROG);

                    return XDP_PASS;
                }

                __u8 deep = lastdomain->recursion_state, pointer = lastdomain->pointer; ip = cache_record.ip;

                if (lastdomain->query.domain_size - pointer <= MAX_SUBDOMAIN_LENGTH && pointer + MAX_SUBDOMAIN_LENGTH <= MAX_DNS_NAME_LENGTH)
                {
                    cache_record.ip = 0;

                    if (bpf_map_update_elem(&cache_nsrecords, &lastdomain->query.name[pointer], &cache_record, BPF_ANY) < 0)
                    {
                        #ifdef ERROR
                            bpf_printk("[XDP] NS Cache map error");
                        #endif

                        return XDP_PASS;
                    }

                    #ifdef DOMAIN
                        bpf_printk("[XDP] NS Cache Updated");
                    #endif
                }

                lastdomain->recursion_state = curr.id.id - 1;
                lastdomain->pointer = curr.id.port;

                struct hop_query *last_of_last = bpf_map_lookup_elem(&new_queries, (struct rec_query_key *) lastdomain);

                if (last_of_last)
                {
                    last_of_last->recursion_state = deep;
                    last_of_last->recursion_state |= (1 << 8);

                    #ifdef DEEP
                        bpf_printk("curr %d", last_of_last->recursion_state);
                    #endif
                }

                else
                {   
                    struct query_owner *powner = bpf_map_lookup_elem(&recursive_queries, (struct rec_query_key *) lastdomain);

                    if (powner)
                    {
                        powner->rec = deep;
                        powner->not_cache = 1;

                        #ifdef DEEP
                            bpf_printk("curr %d", powner->rec);
                        #endif
                    }                    
                }
            }

            else
            {
                __u8 deep = lastdomain->recursion_state;

                lastdomain->recursion_state = curr.id.id - 1;
                lastdomain->pointer = curr.id.port;

                struct hop_query *last_of_last = bpf_map_lookup_elem(&new_queries, (struct rec_query_key *) lastdomain);

                if (last_of_last)
                {
                    last_of_last->recursion_state = deep;

                    #ifdef DEEP
                        bpf_printk("curr %d", last_of_last->recursion_state);
                    #endif
                }

                else
                {
                    struct query_owner *powner = bpf_map_lookup_elem(&recursive_queries, (struct rec_query_key *) lastdomain);

                    if (powner)
                    {
                        powner->rec = deep;

                        #ifdef DEEP
                            bpf_printk("curr %d", powner->rec);
                        #endif
                    }
                }
            }

            bpf_map_delete_elem(&curr_queries, &curr); bpf_map_delete_elem(&new_queries, query);

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

            if (redirect_packet_swap(data, &offset_h, data_end, ip) == DROP)
                return XDP_DROP;

            if (create_dns_query(data, &offset_h, data_end) == DROP)
                return XDP_DROP;

            modify_id(data, lastdomain->recursion_state);

            if (write_query(data, &offset_h, data_end, &lastdomain->query) == DROP)
                return XDP_DROP;

            #ifdef DOMAIN
                bpf_printk("[XDP] New back query created");
            #endif

            bpf_tail_call(ctx, &tail_programs, DNS_UDP_CSUM_PROG);

            return XDP_DROP;
        }

        bpf_map_delete_elem(&curr_queries, &curr);
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

    __u8 status = get_dest_ip(data);
    hide_in_dest_ip(data, data_end, serverip);

    struct curr_query curr = {
        .id.id = get_query_id(data),
        .id.port = get_dest_port(data),
        .ip = get_source_ip(data)
    };

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

                __u16 id = query->id.id - 1, port = query->id.port;

                query = (struct dns_query *) lastdomain;
            
                query->id.id = id; query->id.port = port;
            }

            else
                break;

            lastdomain = bpf_map_lookup_elem(&new_queries, (struct rec_query_key *) query);
        }

        struct query_owner *powner = bpf_map_lookup_elem(&recursive_queries, (struct rec_query_key *) query);
        
        if (powner)
        {
            modify_id(data, query->id.id);

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

            if (redirect_packet_keep(data, &offset_h, data_end, powner->ip) == DROP)
                return XDP_DROP;

            if (create_no_dns_answer(data, &offset_h, data_end, status) == DROP)
                return XDP_DROP;

            if (inter)
            {
                if (write_query(data, &offset_h, data_end, &query->query) == DROP)
                    return XDP_DROP;
            }

            bpf_tail_call(ctx, &tail_programs, DNS_UDP_CSUM_PROG);

            return XDP_DROP;
        }    
    }

    return XDP_DROP;
}

SEC("xdp")
int dns_send_event(struct xdp_md *ctx) {

    #ifdef DOMAIN
        bpf_printk("[XDP] Send event program");
    #endif    

    void *data_end = (void*) (long) ctx->data_end;
    void *data = (void*) (long) ctx->data;

    __u64 offset_h = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header); // Desclocamento d e bits para verificar as informações do pacote

    if (data + offset_h > data_end)
        return XDP_DROP;

    __u32 ip = get_dest_ip(data);
    
    hide_in_dest_ip(data, data_end, serverip);

    __u16 remainder_offset = get_source_port(data);

    hide_in_source_port(data, bpf_htons(DNS_PORT));

    if (remainder_offset > MAX_UDP_SIZE)
        return XDP_DROP;

    struct curr_query curr = {
        .id.id = get_query_id(data),
        .id.port = get_dest_port(data),
        .ip = get_source_ip(data)
    };

    struct dns_query *query = bpf_map_lookup_elem(&curr_queries, &curr);

    if (query) {

        bpf_map_delete_elem(&curr_queries, &curr);

        __u8 *remainder = data + remainder_offset;

        __u32 ips[4];
        
        int count = 0;

        for (int i = 0; i < 20; i++)
        {
            if (remainder + 6 > data_end)
                break;

            else if ((*(remainder) & 0xC0) == 0xC0 && bpf_ntohs(*((__u16 *) (remainder + 2))) == A_RECORD_TYPE && bpf_ntohs(*((__u16 *) (remainder + 4))) == DNS_CLASS_IN)
            {        
                if (remainder + 16 > data_end)
                    break;
                
                __u32 ip = *((__u32 *) (remainder + 12));

                bpf_printk("[XDP] Event IP %d: %u", count, ip);
            
                ips[count++] = *((__u32 *) (remainder + 12));

                remainder += (4 + 12);

                if (count == 4)
                    break;
            }

            else if ((*(remainder) & 0xC0) == 0xC0 && bpf_ntohs(*((__u16 *) (remainder + 2))) == AAA_RECORD_TYPE && bpf_ntohs(*((__u16 *) (remainder + 4))) == DNS_CLASS_IN)
            {
                remainder += (16 + 12);
            }
            
            else
                break;
        }


        if (count)
        {
            struct event *myevent = bpf_ringbuf_reserve(&ringbuf_send_packet, sizeof(struct event), 0);

            if (myevent) {

                __builtin_memcpy(myevent->domain, query->query.name, MAX_DNS_NAME_LENGTH);

                myevent->id = get_query_id(data);
                myevent->port = get_dest_port(data);
                myevent->len = count;
                
                for (size_t i = 0; i < 4; i++)
                    myevent->ips[i] = ips[i];

                bpf_ringbuf_submit(myevent, 0);
            }
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

        if (redirect_packet_swap(data, &offset_h, data_end, ip) == DROP)
            return XDP_DROP;

        if (create_dns_query(data, &offset_h, data_end) == DROP)
            return XDP_DROP;

        #ifdef DOMAIN
            bpf_printk("[XDP] Hop query created");
        #endif

        bpf_tail_call(ctx, &tail_programs, DNS_UDP_CSUM_PROG);

        return XDP_DROP;
    }

    return XDP_DROP;
}

SEC("xdp")
int dns_udp_csum(struct xdp_md *ctx) {

    void *data_end = (void*) (long) ctx->data_end;
    void *data = (void*) (long) ctx->data;

    __u64 offset_h = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

    if (data + offset_h > data_end)
        return XDP_DROP;

    compute_udp_checksum(data, data_end);

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
