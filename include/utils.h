#ifndef UTILS_H
#define UTILS_H

#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_vlan.h>
#include <linux/if_ether.h> 
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/bpf.h>
#include "csum.h"
#include "dns.h"

static __always_inline __u8 get_domain(void *data, __u64 *offset, void *data_end, struct dns_domain *query, __u8 *domain_size)
{
    __u8 *content = (__u8 *)(data + *offset);

    *offset += sizeof(__u8);

    if (data + *offset > data_end)
        return DROP;

    if (*(content) == 0)
    {
        return DROP;
    }

    __builtin_memset(query->name, 0, MAX_DNS_NAME_LENGTH);

    size_t size;

    #pragma unroll
    for (size = 0; (size < MAX_DNS_NAME_LENGTH && *(content + size) != 0); size++)
    {
        query->name[size] =  *(char *)(content + size);
    
        if (data + ++(*offset) > data_end)
            return DROP;
    }
    

    (*domain_size) = (__u8) size;

    content = (__u8 *)(data + *offset); // 0 Octect

    *offset += (sizeof(__u8) * 4);

    if (data + *offset > data_end)
        return DROP;

    if (bpf_ntohs(*((__u16 *) content)) ^ A_RECORD_TYPE)
    {
        return PASS;
    }

    content += 2;

    if (bpf_ntohs(*((__u16 *) content)) ^ DNS_CLASS_IN)
    {

        return PASS;
    }
    
    return ACCEPT;
}

static __always_inline __u8 is_dns_query_or_response(void *data, __u64 *offset, void *data_end, __u16 *id)
{
    struct dns_header *header;
    header = (struct dns_header *)(data + *offset);
    
    *offset  += sizeof(struct dns_header);

    if (data + *offset > data_end)
    {      
        return DROP;
    }

    if (bpf_ntohs(header->questions) > 1)
    {
        return PASS;
    }

    // *id = header->id;
    *id = bpf_ntohs(header->id);


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


static __always_inline __u8 set_dns_header(void *data, __u64 *offset, void *data_end) {

     struct dns_header *header = (struct dns_header *)(data + *offset);

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
     struct dns_header *header = (struct dns_header *)(data + *offset);

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

     struct dns_header *header = (struct dns_header *)(data + *offset);
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
    
     struct dns_response *response = (struct dns_response *)(data + *offset);

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

static __always_inline __u8 get_dns_answer(void *data, __u64 *offset, void *data_end, struct a_record *record) {
  
     struct dns_header *header;
  
     header = (struct dns_header *)(data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr));
     struct dns_response *response;

     response = (struct dns_response *)(data + *offset);

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
             response = (struct dns_response *)(data + *offset);

             *offset += sizeof(struct dns_response);

             if (data + *offset > data_end)
             {
                 #ifdef DOMAIN
                     bpf_printk("[DROP] No DNS answer");
                 #endif
                 return DROP;
             }
         }

         if (bpf_ntohs(response->record_type) != A_RECORD_TYPE)
             return ACCEPT_NO_ANSWER;

         if (bpf_ntohs(response->record_class) != DNS_CLASS_IN)
             return ACCEPT_NO_ANSWER;

         record->ip = response->ip;
         record->timestamp = (bpf_ktime_get_ns() / 1000000000) + bpf_ntohl(response->ttl);

         #ifdef DOMAIN
             bpf_printk("[XDP] Answer IP: %u", record->ip);
         #endif
        
         return ACCEPT;
     }

     else if (bpf_ntohs(header->name_servers))
     {
         *offset += sizeof(struct dns_response);

         if (data + *offset > data_end)
         {
             #ifdef DOMAIN
                 bpf_printk("[DROP] No DNS answer");
             #endif

             return DROP;
         }

         if (bpf_ntohs(response->record_type) != SOA_RECORD_TYPE)
             return ACCEPT_NO_ANSWER;

         if (bpf_ntohs(response->record_class) != DNS_CLASS_IN)
             return ACCEPT_NO_ANSWER;

         record->ip = 0;
         record->timestamp = (bpf_ktime_get_ns() / 1000000000) + bpf_ntohl(response->ttl);
        
         return ACCEPT;  
     }
    
     return ACCEPT_NO_ANSWER;
 }


static __always_inline __u8 format_network_acess_layer(void *data, __u64 *offset, void *data_end)
{
     struct ethhdr *eth = (struct ethhdr *)(data);

     *offset = sizeof(struct ethhdr);

     if (data + *offset > data_end)
     {
         #ifdef DOMAIN
             bpf_printk("[DROP] Boundary exceded");
         #endif

         return DROP;
     }

 	__builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
 	
    eth->h_source[0] = 0xa0;
    eth->h_source[1] = 0x36;
    eth->h_source[2] = 0x9f;
    eth->h_source[3] = 0x19;
    eth->h_source[4] = 0xc4;
    eth->h_source[5] = 0xcc;


     return ACCEPT;
 }


static __always_inline __u8 swap_internet_layer(void *data, __u64 *offset, void *data_end)
{
    struct iphdr *ipv4 = (struct iphdr *)(data + *offset);
    *offset += sizeof(struct iphdr);
    if (data + *offset > data_end)
        return DROP;

    __be32 tmp_ip = ipv4->saddr;
    ipv4->saddr = ipv4->daddr;
    ipv4->daddr = tmp_ip;

    __u16 old_ttl_word = bpf_htons((__u16)ipv4->ttl << 8);
    __u16 old_len      = ipv4->tot_len;

    ipv4->ttl     = 255;
    ipv4->tot_len = bpf_htons((data_end - data) - sizeof(struct ethhdr));

    __u32 csum = csum_unfold(ipv4->check);

    __u16 new_ttl_word = bpf_htons((__u16)ipv4->ttl << 8);
    csum += (__u32)(__u16)~old_ttl_word + (__u32)new_ttl_word;

    csum += (__u32)(__u16)~old_len + (__u32)ipv4->tot_len;

    ipv4->check = csum_fold_neg(csum);

    return ACCEPT;
}

static __always_inline __u8 keep_transport_layer(void *data, __u64 *offset, void *data_end)
{
     struct udphdr *udp = (struct udphdr *)(data + *offset);

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
     struct udphdr *udp = (struct udphdr *)(data + *offset);

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


#endif
