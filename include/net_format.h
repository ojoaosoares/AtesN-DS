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

static __always_inline __u8 send_dns_response_hw(void *data, void *data_end, __u32 ip, __u32 ttl, __u8 status, __u8 domain_size)
{
    if ((void *)((__u8 *)data + DNS_QUESTION_OFFSET) > data_end)
        return DROP;

    // 1. Swap Ethernet MACs
    struct ethhdr *eth = (struct ethhdr *)data;
    __u32 tmp_mac4 = *(__u32 *)eth->h_dest;
    __u16 tmp_mac2 = *(__u16 *)(eth->h_dest + 4);
    *(__u32 *)eth->h_dest = *(__u32 *)eth->h_source;
    *(__u16 *)(eth->h_dest + 4) = *(__u16 *)(eth->h_source + 4);
    *(__u32 *)eth->h_source = tmp_mac4;
    *(__u16 *)(eth->h_source + 4) = tmp_mac2;

    // 2. Swap IP addresses & update TTL/Length/Checksum (RFC 1624)
    struct iphdr *ipv4 = (struct iphdr *)((__u8 *)data + IPV4_OFFSET);
    __be32 tmp_ip = ipv4->saddr;
    ipv4->saddr   = ipv4->daddr;
    ipv4->daddr   = tmp_ip;

    __u16 old_ttl_proto = *((__u16 *)&ipv4->ttl);
    __u16 old_tot_len   = ipv4->tot_len;

    ipv4->ttl     = 255;
    ipv4->tot_len = bpf_htons((__u16)(((__u8 *)data_end - (__u8 *)data) - ETH_HLEN_BYTES));

    __u32 csum  = (__u32)((__u16)~ipv4->check);
    csum       += (__u32)((__u16)~old_ttl_proto) + (__u32)((UDP_PROTOCOL << 8) | 255);
    csum       += (__u32)((__u16)~old_tot_len)   + (__u32)ipv4->tot_len;
    csum        = (csum >> 16) + (csum & 0xffff);
    csum       += (csum >> 16);
    ipv4->check = ~((__u16)csum);

    // 3. Swap UDP ports & update length
    struct udphdr *udp = (struct udphdr *)((__u8 *)data + UDP_OFFSET);
    __be16 tmp_port = udp->source;
    udp->source = udp->dest;
    udp->dest   = tmp_port;
    udp->len    = bpf_htons((__u16)(((__u8 *)data_end - (__u8 *)data) - UDP_OFFSET));
    udp->check  = 0;

    // 4. DNS Header
    struct dns_header *dns = (struct dns_header *)((__u8 *)data + DNS_OFFSET);
    dns->flags = bpf_htons(DNS_FLAG_RESPONSE_BASE + status);
    dns->name_servers = 0;
    dns->additional_records = 0;

    if (ip != 0) {
        dns->answer_count = bpf_htons(1);
        struct dns_response *resp = (struct dns_response *)((__u8 *)data + DNS_QUESTION_OFFSET + domain_size + DNS_QTAIL_LEN);
        if ((void *)(resp + 1) > data_end)
            return DROP;
        resp->query_pointer = bpf_htons(DNS_POINTER_OFFSET);
        resp->record_type   = bpf_htons(A_RECORD_TYPE);
        resp->record_class  = bpf_htons(DNS_CLASS_IN);
        resp->ttl           = bpf_htonl(ttl);
        resp->data_length   = bpf_htons(sizeof(ip));
        resp->ip            = ip;
    } else {
        dns->answer_count = 0;
    }

    return ACCEPT;
}

#endif
