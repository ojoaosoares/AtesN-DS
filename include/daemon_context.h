#ifndef DAEMON_CONTEXT_H
#define DAEMON_CONTEXT_H

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <sched.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "dns.h"
#include "daemon_timing_wheel.h"

#define DEFAULT_HW_CACHE_PATH      "/sys/fs/bpf/level_one_cache"
#define DEFAULT_TIME_MAP_PATH      "/sys/fs/bpf/time_map"
#define DEFAULT_RINGBUF_PATH       "/sys/fs/bpf/hw_sync_ringbuf"
#define DEFAULT_HW_CACHE_CAPACITY  32768  /* Sized for SmartNIC on-chip SRAM fabric */

struct daemon_config {
    char hw_cache_path[256];
    char time_map_path[256];
    char ringbuf_path[256];
    uint32_t hw_cache_capacity;
    uint32_t high_watermark_pct;
    uint32_t low_watermark_pct;
    char resolver_ringbuf_path[256];
    int ingest_core;
    int governance_core;
    int resolver_core;
    __u32 resolver_src_ip;
    char warmup_trace[256];
    uint32_t warmup_ttl;
    bool verbose;
};

struct daemon_ctx {
    struct daemon_config cfg;
    int hw_cache_fd;
    int time_map_fd;
    int ringbuf_map_fd;
    int resolver_ringbuf_fd;
    struct ring_buffer *rb;
    struct ring_buffer *rb_resolver;
    struct timing_wheel *wheel;
    volatile bool running;

    /* Metrics */
    uint64_t total_ingested;
    uint64_t total_expired_deleted;
    uint64_t total_lru_evicted;
    uint64_t total_passive_evicted;
};

static inline void pin_to_core(int core_id) {
    if (core_id < 0) return;
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) != 0) {
        fprintf(stderr, "[WARN] Could not pin thread to core %d: %s\n", core_id, strerror(errno));
    }
}

#endif /* DAEMON_CONTEXT_H */
