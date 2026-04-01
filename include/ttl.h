#ifndef TTL_H
#define TTL_H

#include <linux/types.h>
#include <bpf/bpf_helpers.h>

static __always_inline __u32 get_ttl(__u32 timestamp, __u32 now) {
    if (now >= timestamp)
        return 0;
    return timestamp - now;
}

#endif