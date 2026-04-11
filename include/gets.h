#ifndef GETS_H
#define GETS_H

#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_ether.h> 
#include <linux/types.h>
#include <bpf/bpf_endian.h>

#include "dns.h"

static __always_inline __u16 get_query_id(void *data)
{
    struct dns_header *header = (struct dns_header *) (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr));

    return bpf_ntohs(header->id);
}

static __always_inline __u16 get_source_port(void *data)
{
    struct udphdr *udp = (struct udphdr *) (data + sizeof(struct ethhdr) + sizeof(struct iphdr));

    return bpf_ntohs(udp->source);
}

static __always_inline __u16 get_dest_port(void *data)
{
    struct udphdr *udp = (struct udphdr *) (data + sizeof(struct ethhdr) + sizeof(struct iphdr));

    return bpf_ntohs(udp->dest);
}

static __always_inline __u32 get_source_ip(void *data)
{
    struct iphdr *ipv4 = (struct iphdr *) (data + sizeof(struct ethhdr));

    return ipv4->saddr;
}

static __always_inline __u32 get_dest_ip(void *data)
{   
    struct iphdr *ipv4 = (struct iphdr *) (data + sizeof(struct ethhdr));

    return ipv4->daddr;
}

static __always_inline __s64 get_query_id_safe(void *data, void *data_end)
{
    struct dns_header *header = (struct dns_header *) (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr));

    if (((void *) header) + sizeof(struct dns_header) > data_end)
        return -1;

    return bpf_ntohs(header->id);
}

static __always_inline __s64 get_source_port_safe(void *data, void *data_end)
{
    struct udphdr *udp = (struct udphdr *) (data + sizeof(struct ethhdr) + sizeof(struct iphdr));

    if (((void *) udp) + sizeof(struct udphdr) > data_end)
        return -1;

    return bpf_ntohs(udp->source);
}

static __always_inline __s64 get_dest_port_safe(void *data, void *data_end)
{
    struct udphdr *udp = (struct udphdr *) (data + sizeof(struct ethhdr) + sizeof(struct iphdr));

    if (((void *) udp) + sizeof(struct udphdr) > data_end)
        return -1;

    return bpf_ntohs(udp->dest);
}

static __always_inline __s64 get_source_safe(void *data, void *data_end)
{
    struct iphdr *ip = (struct iphdr *) (data + sizeof(struct ethhdr));

    if (((void *) ip) + sizeof(struct iphdr) > data_end)
        return -1;

    return ip->saddr;
}

static __always_inline __s64 get_dest_ip_safe(void *data, void *data_end)
{
    struct iphdr *ip = (struct iphdr *) (data + sizeof(struct ethhdr));

    if (((void *) ip) + sizeof(struct iphdr) > data_end)
        return -1;

    return ip->daddr;
}

#endif