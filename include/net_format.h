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

    unsigned char copy[ETH_ALEN];
    __builtin_memcpy(copy, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, copy, ETH_ALEN);
    
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

    __u32 new_ttl = 255;
    ipv4->ttl = new_ttl;

    __u32 new_len = bpf_htons((uint16_t)(((__u8 *)data_end - (__u8 *)data) - sizeof(struct ethhdr)));
    ipv4->tot_len = new_len;

    ipv4->check = calculate_ip_checksum(ipv4);
    return ACCEPT;
}

static __always_inline __u8 swap_internet_layer_hw(void *data, __u64 *offset, void *data_end)
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

    // swap src/dst
    __be32 tmp_ip  = ipv4->saddr;
    ipv4->saddr    = ipv4->daddr;
    ipv4->daddr    = tmp_ip;

    // guarda campos antigos antes de modificar
    __u16 old_ttl_proto = *((__u16 *)&ipv4->ttl);   // ttl+protocol juntos como word
    __u16 old_tot_len   = ipv4->tot_len;

    // aplica novos valores
    ipv4->ttl     = 255;
    ipv4->tot_len = bpf_htons((__u16)(((__u8 *)data_end - (__u8 *)data) - sizeof(struct ethhdr)));

    __u16 new_ttl_proto = *((__u16 *)&ipv4->ttl);
    __u16 new_tot_len   = ipv4->tot_len;

    // atualização incremental RFC 1624
    // check = ~(~check + ~old + new)
    __u32 csum  = (__u32)((__u16)~ipv4->check);
    csum       += (__u32)((__u16)~old_ttl_proto) + (__u32)new_ttl_proto;
    csum       += (__u32)((__u16)~old_tot_len)   + (__u32)new_tot_len;

    // fold e complemento final
    csum        = (csum >> 16) + (csum & 0xffff);
    csum       += (csum >> 16);
    ipv4->check = ~((__u16)csum);

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
