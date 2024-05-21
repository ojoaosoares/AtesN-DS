#include "in.h"
#include "ip.h"
#include "udp.h" // In udp we verifiy if the source port is 53
#include "if_vlan.h" // Essential to verify the ip type
#include "if_ether.h" // Essential for ethernet headers
#include "if_packet.h"
#include "bpf.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"

#define IPV4 0x0800
#define IP_FRAGMENTET 65343
#define UDP_PROTOCOL 0x11
#define DNS_PORT 0x35

#define DEBUG

static __always_inline void print_ip(__u64 ip) {

    __u8 fourth = ip >> 24;
    __u8 third = (ip >> 16) & 0xFF;
    __u8 second = (ip >> 8) & 0xFF;
    __u8 first = ip & 0xFF;

    #ifdef DEBUG
        bpf_printk("IP: %d.%d.%d.%d", first, second, third, fourth);
    #endif

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
            bpf_printk("[DROP] Ethernet type isn't IPV4, %d != %d", ip_type, bpf_htons(IPV4));
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
            bpf_printk("[DROP] Ip protocol isn't UDP, %d != %d", transport_protocol, UDP_PROTOCOL);
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

    if (bpf_ntohs(udp->source) != DNS_PORT)
    {
        #ifdef DEBUG
            bpf_printk("[DROP] UDP datagram isn't port 53, %d %d != %d ", bpf_ntohs(udp->source), DNS_PORT);
        #endif
        return 0;
    }

    return 1;
}

SEC("dns_filter")
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

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";