#ifndef DNS_REDIRECT_H
#define DNS_REDIRECT_H

#include <linux/types.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "dns.h"
#include "csum.h"
#include "net_format.h"

static __always_inline __u8 hide_in_dest_ip_safe(void *data, void *data_end, __u32 hidden)
{   
    struct iphdr *ipv4 = (struct iphdr *)((__u8 *)data + sizeof(struct ethhdr));
    if ((void *)((__u8 *)data + sizeof(struct ethhdr) + sizeof(struct iphdr)) > data_end)
        return DROP;
    ipv4->daddr = hidden;
    return ACCEPT;
}

static __always_inline void hide_in_source_port(void *data, __u16 hidden)
{   
    struct udphdr *udp = (struct udphdr *)((__u8 *)data + sizeof(struct ethhdr) + sizeof(struct iphdr));
    udp->source = hidden;
}

static __always_inline __u8 hide_in_source_port_safe(void *data, void *data_end, __u16 hidden)
{   
    struct udphdr *udp = (struct udphdr *)((__u8 *)data + sizeof(struct ethhdr) + sizeof(struct iphdr));

    if ((void *)((__u8 *)data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr)) > data_end)
        return DROP;

    udp->source = hidden;
    return ACCEPT;
}

static __always_inline __u8 return_to_network(void *data, __u64 *offset, void *data_end, __u32 ip_dest, __u32 serverip) {
    struct iphdr *ipv4 = (struct iphdr *)((__u8 *)data + *offset);
    *offset += sizeof(struct iphdr);
    if ((void *)((__u8 *)data + *offset) > data_end)
        return DROP;

    ipv4->saddr = serverip;
    ipv4->daddr = ip_dest;

    __u32 new_ttl = 255;
    ipv4->ttl = new_ttl;

    __u32 new_len = bpf_htons((uint16_t)(((__u8 *)data_end - (__u8 *)data) - sizeof(struct ethhdr)));
    ipv4->tot_len = new_len;

    ipv4->check = calculate_ip_checksum(ipv4);
    return ACCEPT;
}

static __always_inline __u8 redirect_packet_keep(void *data, __u64 *offset, void *data_end, __u32 ip, __u32 serverip, unsigned char *gateway_mac)
{
    if (format_network_access_layer_sw(data, offset, data_end, gateway_mac) == DROP) 
        return DROP;
    if (return_to_network(data, offset, data_end, ip, serverip) == DROP)
        return DROP;
    if (keep_transport_layer(data, offset, data_end) == DROP)
        return DROP;
    return ACCEPT;
}

static __always_inline __u8 redirect_packet_swap(void *data, __u64 *offset, void *data_end, __u32 ip, __u32 serverip, unsigned char *gateway_mac)
{
    if (format_network_access_layer_sw(data, offset, data_end, gateway_mac) == DROP) 
        return DROP;
    if (return_to_network(data, offset, data_end, ip, serverip) == DROP)
        return DROP;
    if (swap_transport_layer(data, offset, data_end) == DROP)
        return DROP;
    return ACCEPT;
}

#endif
