#ifndef DNS_LISTENER_H
#define DNS_LISTENER_H

#include <stdint.h>
#include <stdbool.h>
#include <linux/if_link.h>
#include "dns.h"

#define DEFAULT_LISTENER_IFACE      "enp1s0np1"
#define DEFAULT_HW_SYNC_RINGBUF     "/sys/fs/bpf/hw_sync_ringbuf"

struct listener_config {
    char interface[64];
    char ringbuf_path[256];
    bool verbose;
    bool daemonize;
};

struct listener_stats_val {
    uint64_t egress_queries_tracked;
    uint64_t ingress_responses_matched;
    uint64_t sync_events_submitted;
};

#endif /* DNS_LISTENER_H */
