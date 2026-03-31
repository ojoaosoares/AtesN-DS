#ifndef DNS_FILTER_H
#define DNS_FILTER_H

#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_vlan.h>
#include <linux/if_ether.h> 
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "dns.h"

static __always_inline __u8 is_ipv4(void *data, __u64 *offset, void *data_end)
{
    struct ethhdr *eth = (struct ethhdr *)data;

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
    ipv4 = (struct iphdr *)(data + *offset);

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
    struct udphdr *udp =  (struct udphdr *)(data + *offset);
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

static __always_inline __u8 filter_dns(void *data, __u64 *offset,  void *data_end)
{
    switch (is_ipv4(data, offset, data_end))
    {
        case DROP:
            return DROP;
        case PASS:
            return PASS;
        default:
            break;
    }

    switch (is_valid_udp(data, offset, data_end))
    {
        case DROP:
            return DROP;
        case PASS:
            return PASS;
        default:
            break;
    }

    switch (is_port_53(data, offset, data_end))
    {
        case DROP:
            return DROP;
        case PASS:
            return PASS;
        case TO_DNS_PORT:
            break;
        case FROM_DNS_PORT:
            return FROM_DNS_PORT;
            break;
    }

    return ACCEPT;
}

#endif
