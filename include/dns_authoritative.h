#ifndef DNS_AUTHORITATIVE_H
#define DNS_AUTHORITATIVE_H

#include <linux/types.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "dns.h"

static __always_inline __u8 get_pointer(void *data, __u64 *offset, void *data_end, __u8 *pointer) {
    __u8 *content = (__u8 *)data + *offset;
    if ((void *)((__u8 *)data + *offset + 2) > data_end)
        return DROP;

    *pointer = 0;
    if ((*content & 0xC0) == 0xC0)
        *pointer = (__u8) (bpf_ntohs(*((__u16 *) (content))) & 0x3FFF) - sizeof(struct dns_header);

    return ACCEPT;
}

static __always_inline __u8 get_additional(void *data, __u64 *offset, void *data_end, struct a_record_sw *record, __u8 domainsize, __u8 **remainder) {
    record->ip = 0;
    record->timestamp = 0;

    __u8 *content = (__u8 *)data + *offset;

    #pragma unroll
    for (size_t size = 0; size < MAX_DNS_PAYLOAD; size++) {

        if (size >= MAX_DNS_PAYLOAD  - domainsize)
            break;

        if ((void *)(content + size + 16) > data_end)
            break;

        __u16 marker = *((__u16 *)(content + size));

        if ((marker & 0xC0C0) != 0xC000)
            continue;

        __u16 rtype = bpf_ntohs(*((__u16 *)(content + size + 2)));
        __u16 rclass = bpf_ntohs(*((__u16 *)(content + size + 4)));

        if (rtype != A_RECORD_TYPE || rclass != DNS_CLASS_IN)
            continue;

        __u32 ttl = bpf_ntohl(*((__u32 *)(content + size + 6)));
        record->ip = *((__u32 *)(content + size + 12));
        *remainder = content + size + 16;

        record->timestamp = (bpf_ktime_get_ns() / 1000000000) + ttl;
        return ACCEPT;
    }

    return ACCEPT_NO_ANSWER;
}

static __always_inline __u8 get_authoritative_pointer(void *data, __u64 *offset, void *data_end, __u8 *pointer, __u8 *off,  struct dns_domain_sw *domain, struct dns_domain_sw *subdomain)
{
    __builtin_memset(&subdomain->name, 0, MAX_DNS_NAME_LENGTH_SW);
    __u8 *content = (__u8 *)data + *offset;

    if ((void *)((__u8 *)data + *offset + 1) > data_end)
        return DROP;

    if (*content == 0) {
        (*offset)++;
        return ACCEPT_JUST_POINTER;
    }

    if ((void *)((__u8 *)data + *offset + 2) > data_end)
        return DROP;

    if ((*(content) & 0xC0) == 0xC0) {
        *offset += 2;
        *pointer = (__u8) ((bpf_ntohs(*(__u16 *) content) & 0x3FFF) - sizeof(struct dns_header));
        *off += 2;
        return ACCEPT_JUST_POINTER;
    }

    size_t size;
    for (size = 0; size < MAX_DNS_NAME_LENGTH_SW; size++) {
        if ((void *)((__u8 *)data + ++(*offset)) > data_end)
            return DROP;

        if (*(content + size) == 0) {
            (*off) += (uint8_t)(size + 1);
            subdomain->domain_size = (uint8_t)size;
            return ACCEPT;
        }

        if ((*(content + size) & 0xC0) == 0xC0) {
            if ((void *)((__u8 *)data + (*offset) + 1) > data_end)
                return DROP;
            *pointer = (__u8) ((bpf_ntohs(*(__u16 *) (content + size)) & 0x3FFF) - sizeof(struct dns_header));
            (*off) += (uint8_t)(size + 2);
            subdomain->domain_size = (uint8_t) (size + (domain->domain_size - *pointer));
            return ACCEPT;
        }
        subdomain->name[size] = *(content + size);
    }
    return DROP;
}

static __always_inline __u8 get_authoritative(void *data, __u64 *offset, void *data_end, struct dns_domain_sw *autho, struct dns_domain_sw *query, __u16 off) {

    __u64 base = *offset + query->domain_size + 5 + off;

    if ((void *)((__u8 *)data + base + 12) > data_end)
        return DROP;

    __u8 *type    = (__u8 *)data + base;
    __u8 *content = (__u8 *)data + base + 10;

    if (*((__u16 *)type) == SOA_RECORD_TYPE)
        return ACCEPT_NO_ANSWER;

    __u16 temp_size = bpf_ntohs(*((__u16 *)content));
    if (temp_size > MAX_DNS_NAME_LENGTH_SW)
        return DROP;

    autho->domain_size = temp_size;

    content += 2;

    __u64 newoff = *offset;
    __u8 *domain = (__u8 *)data + newoff;
    __u64 cur = base + 12;
    *offset = cur;

    for (size_t size = 0; size < autho->domain_size; size++) {

        if ((void *)((__u8 *)data + cur + 1) > data_end)
            return ACCEPT_NO_ANSWER;

        if ((*(content + size) & 0xC0) == 0xC0) {

            if ((void *)((__u8 *)data + cur + 2) > data_end)
                return DROP;

            __u8 pointer = (uint8_t) ((bpf_ntohs(*((__u16 *) (content + size))) & 0x3FFF) - sizeof(struct dns_header));

            if (pointer >= query->domain_size)
                return DROP;

            if (size > MAX_DNS_NAME_LENGTH_SW || pointer > MAX_DNS_NAME_LENGTH_SW)
                return DROP;

            autho->domain_size += (uint8_t)((query->domain_size - pointer) - 2);
            autho->name[size] = query->name[pointer];

            for (size_t i = 0; pointer + i < MAX_DNS_NAME_LENGTH_SW; i++) {
                if ((void *)((__u8 *)data + newoff + 1) > data_end)
                    return DROP;
                *(domain) = query->name[pointer + i];
                if (*(domain++) == 0)
                    break;
                newoff++;
            }

            __u64 woff = sizeof(struct ethhdr) + sizeof(struct iphdr) +
                         sizeof(struct udphdr) + sizeof(struct dns_header) +
                         autho->domain_size;

            if ((void *)((__u8 *)data + woff + 6) > data_end)
                return DROP;

            domain   = (__u8 *)data + woff;
            *domain++ = 0;
            *((__u16 *) domain) = bpf_htons(A_RECORD_TYPE);
            domain += 2;
            *((__u16 *) domain) = bpf_htons(DNS_CLASS_IN);
            return ACCEPT;
        }

        autho->name[size] = *(content + size);

        if ((void *)((__u8 *)data + newoff + 1) > data_end)
            return DROP;

        *(domain++) = autho->name[size];
        newoff++;
        cur++;
    }

    __u64 woff = sizeof(struct ethhdr) + sizeof(struct iphdr) +
                 sizeof(struct udphdr) + sizeof(struct dns_header) +
                 autho->domain_size - 1;

    if ((void *)((__u8 *)data + woff + 6) > data_end)
        return DROP;

    domain = (__u8 *) data + woff;
    *((__u16 *) domain) = bpf_htons(A_RECORD_TYPE);
    domain += 2;
    *((__u16 *) domain) = bpf_htons(DNS_CLASS_IN);
    return ACCEPT;
}

#endif
