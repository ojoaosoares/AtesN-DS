#ifndef DNS_OWNER_H
#define DNS_OWNER_H

#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include "dns.h"
#include "ttl.h"

static __always_inline __u8 find_owner_server(struct dns_domain_sw *domain, __u32 *ip, __u8 *pointer) { 
    __u64 index = 0;
    for (size_t i = 0; i < MAX_LABELS_CHECK && (index < MAX_DNS_NAME_LENGTH_SW) && (index + MAX_SUBDOMAIN_LENGTH <= MAX_DNS_NAME_LENGTH_SW); i++)
    {
        if(domain->name[index] == 0) {
            *pointer = (uint8_t)index;
            return 0;
        }

        if (domain->domain_size - index <= MAX_SUBDOMAIN_LENGTH) {
            struct a_record_sw *nsrecord = bpf_map_lookup_elem(&cache_nsrecords, &domain->name[index]);
            if (nsrecord) {
                __u64 diff = get_ttl_sw(nsrecord->timestamp);
                if (!nsrecord->ip)
                    continue;

                if (diff > MINIMUM_TTL) {
                    *ip = nsrecord->ip;
                    *pointer = (uint8_t)index;
                    return 0;
                } else {
                    bpf_map_delete_elem(&cache_nsrecords, &domain->name[index]);
                }
            }
        }
        index += domain->name[index] + 1;
    }
    *pointer = (uint8_t)index;
    return 0;
}

#endif
