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

SEC("dns_filter")
int dns(struct xdp_md *ctx) {

}

char _license[] SEC("license") = "GPL";