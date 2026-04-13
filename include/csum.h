#ifndef CSUM_H
#define CSUM_H

#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_ether.h> 
#include <bpf/bpf_helpers.h>
#include "dns.h"

static __always_inline __u16 csum_fold_neg(__u32 csum)
{
    __u32 sum;
    sum = (csum >> 16) + (csum & 0xffff);
    sum += (sum >> 16);
    return ~((__u16)sum);
}

static __always_inline __u32 csum_unfold(__u16 csum)
{
    return (__u32)csum;
}

static __always_inline __u16 cal_udp_csum(struct iphdr *iph, struct udphdr *udph, void *data_end)
{
    __u32 csum_buffer = 0;
    __u16 *buf = (__u16 *)udph;

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
    struct iphdr *ipv4 = (struct iphdr *) data + sizeof(struct ethhdr);
    struct udphdr *udph = (struct udphdr *) data + sizeof(struct ethhdr) + sizeof(struct iphdr);

    udph->check = cal_udp_csum(ipv4, udph, data_end);
}

static inline __u16 calculate_ip_checksum(struct iphdr *ip)
{
    ip->check = 0;
    __u32 csum = bpf_csum_diff(0, 0, (unsigned int *) ip, sizeof(struct iphdr), 0);
    
    return csum_fold_neg(csum);
}

#endif
