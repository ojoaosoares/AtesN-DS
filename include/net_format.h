#ifndef NET_FORMAT_H
#define NET_FORMAT_H

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "dns.h"
#include "csum.h"

static __always_inline __u8 format_network_access_layer_sw(void *data, __u64 *offset, void *data_end, unsigned char *gateway_mac)
{
    struct ethhdr *eth = (struct ethhdr *)(data);
    *offset = sizeof(struct ethhdr);
    if (data + *offset > data_end)
        return DROP;

    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, gateway_mac, ETH_ALEN);
    return ACCEPT;
}

static __always_inline __u8 format_network_access_layer_hw(void *data, __u64 *offset, void *data_end)
{
    struct ethhdr *eth = (struct ethhdr *)(data);
    *offset = sizeof(struct ethhdr);
    if (data + *offset > data_end)
        return DROP;

    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    eth->h_source[0] = 0xa0;
    eth->h_source[1] = 0x36;
    eth->h_source[2] = 0x9f;
    eth->h_source[3] = 0x19;
    eth->h_source[4] = 0xc4;
    eth->h_source[5] = 0xcc;
    return ACCEPT;
}

static __always_inline __u8 swap_internet_layer_sw(void *data, __u64 *offset, void *data_end)
{
    struct iphdr *ipv4 = (struct iphdr *)(data + *offset);
    *offset += sizeof(struct iphdr);
    if (data + *offset > data_end)
        return DROP;

    __be32 tmp_ip = ipv4->saddr;
    ipv4->saddr = ipv4->daddr;
    ipv4->daddr = tmp_ip;

    __u32 csum = csum_unfold(ipv4->check);
    __u32 new_ttl = 255;
    __u32 old_ttl = ipv4->ttl;
    ipv4->ttl = new_ttl;
    csum = bpf_csum_diff(&old_ttl, sizeof(__u32), &new_ttl, sizeof(__u32), csum);

    __u32 old_len = ipv4->tot_len;
    __u32 new_len = bpf_htons((uint16_t)(((__u8 *)data_end - (__u8 *)data) - sizeof(struct ethhdr)));
    ipv4->tot_len = new_len;
    csum = bpf_csum_diff(&old_len, sizeof(__u32), &new_len, sizeof(__u32), csum);

    ipv4->check = csum_fold_neg(csum);
    return ACCEPT;
}

static __always_inline __u8 swap_internet_layer_hw(void *data, __u64 *offset, void *data_end)
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
    ipv4->tot_len = bpf_htons((uint16_t)(((__u8 *)data_end - (__u8 *)data) - sizeof(struct ethhdr)));

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
        return DROP;

    udp->len = (__u16) bpf_htons((uint16_t)(((__u8 *)data_end - (__u8 *)data) - sizeof(struct ethhdr) - sizeof(struct iphdr)));
    udp->check = bpf_htons(UDP_NO_ERROR);
    return ACCEPT;
}

static __always_inline __u8 swap_transport_layer(void *data, __u64 *offset, void *data_end)
{
    struct udphdr *udp = (struct udphdr *)(data + *offset);
    *offset += sizeof(struct udphdr);
    if (data + *offset > data_end)
        return DROP;

    __be16 tmp_port = udp->source;
    udp->source = udp->dest;
    udp->dest = tmp_port;
    
    udp->len = (__u16) bpf_htons((uint16_t)(((__u8 *)data_end - (__u8 *)data) - sizeof(struct ethhdr) - sizeof(struct iphdr)));
    udp->check = bpf_htons(UDP_NO_ERROR);
    return ACCEPT;    
}

#endif
