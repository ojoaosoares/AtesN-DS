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
        __uint(max_entries, 4556);
        __uint(key_size, sizeof(struct dns_query));
        __uint(value_size, sizeof(struct a_record));
} dns_records SEC(".maps");

static __always_inline void print_ip(__u64 ip) {

    __u8 fourth = ip >> 24;
    __u8 third = (ip >> 16) & 0xFF;
    __u8 second = (ip >> 8) & 0xFF;
    __u8 first = ip & 0xFF;

    #ifdef DEBUG
        bpf_printk("IP: %d.%d.%d.%d", first, second, third, fourth);
    #endif

}

static __always_inline __u64 ip_to_int(char *ip) {

    __u64 final_sum = 0;
    __u8 cont = 0;

    __u16 octet = 256;
    __u8 octet_cont = 0;
    
    __u8 digits[3];

    #pragma unroll
    for (__u8 i = 0; i < 15; i++)
    {
        
        if(ip[i] == '.' || ip[i] == '\0' || cont == 3)
        {
            __u16 p, sum = 0;

            #pragma unroll
            for (__u8 j = 0; j < 3; j++)
            {
                if (cont)
                {
                    p = digits[j];

                    #pragma unroll
                    for (__u8 k = 0; k < 2; k++) 
                    {
                        if (cont - 1 > k)
                            p *= 10;
                    }

                    cont--;

                    sum += p;
                }
            }
                
            __u64 octet_p = 1;
            for (__u8 j = 0; j < 3; j++)
            {
                if(octet_cont > j)
                    octet_p *= octet;
            }

            octet_cont++;
            final_sum += (sum*octet_p);

        }

        else {
            digits[cont] = ip[i] - 48;
            cont++;
        }
    }   

    return final_sum;
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

    if(ip_type != bpf_htons(IPV4))
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

    if (transport_protocol != UDP_PROTOCOL)
    {
        #ifdef DEBUG
            bpf_printk("[DROP] Ip protocol isn't UDP. Protocol: %d", transport_protocol);
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

    if (bpf_ntohs(udp->dest) != DNS_PORT)
    {
        #ifdef DEBUG
            bpf_printk("[DROP] UDP datagram isn't port 53. Port: %d ", bpf_ntohs(udp->dest));
        #endif
        return 0;
    }

    return 1;
}

static __always_inline int isDNSQuery(void *data, __u64 *offset, void *data_end)
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

    if (!(header->query_or_response & DNS_QUERY_TYPE))
    {
        #ifdef DEBUG
            bpf_printk("[DROP] It's not a DNS query");
        #endif
        
        return 0;
    }

    return 1;
}

static __always_inline int getDomain(void *data, __u64 *offset, void *data_end, struct dns_query *query )
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

    if (query->record_type ^ 1)
    {
        #ifdef DEBUG
            bpf_printk("[DROP] It's not a DNS query type A");
        #endif
        return 0;
    }
    
    content += 2;

    query->class = bpf_htons(*((uint16_t *) content));

    if (query->class ^ 1)
    {
        #ifdef DEBUG
            bpf_printk("[DROP] It's not a DNS query class IN");
        #endif
        return 0;
    }
    
    return 1;
}


SEC("xdp")
int dns(struct xdp_md *ctx) {

    void *data_end = (void*) (long) ctx->data_end;
    void *data = (void*) (long) ctx->data;

    __u64 offset_h; // Desclocamento d e bits para verificar as informações do pacote
    int a, b, c;

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

    if (isDNSQuery(data, &offset_h, data_end))
    {
        #ifdef DEBUG
            bpf_printk("Its DNS Query");
        #endif
    }

    else
        return XDP_PASS;

    struct dns_query query;

    if(getDomain(data, &offset_h, data_end, &query))
    {
        #ifdef DEBUG
            bpf_printk("Domain requested: %s", query.name);
            bpf_printk("Domain type: %d", query.record_type);
            bpf_printk("Domain class: %d", query.class);
        #endif
    }

    else 
        return XDP_PASS;
    
    struct a_record *record;
    record = bpf_map_lookup_elem(&dns_records, &query);

    if (record > 0)
    {
        #ifdef DEBUG

            bpf_printk("aqui %d", record->ip_addr);
        #endif
    }


    #ifdef DEBUG
        bpf_printk("Perfect");
    #endif
    
    return XDP_PASS;
}


char _license[] SEC("license") = "GPL";