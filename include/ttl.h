#ifndef TTL_H
#define TTL_H

#include <linux/types.h>
#include <bpf/bpf_helpers.h>

static __always_inline __u32 get_ttl_hw(__u32 timestamp, __u32 now) {
    if (now >= timestamp)
        return 0;
    return timestamp - now;
}

static __always_inline __u64 get_ttl_sw(__u64 timestamp) {
    __u64 now = bpf_ktime_get_ns() / 1000000000;

    if (now >= timestamp)
        return 0;

    return timestamp - now;
}

#endif
