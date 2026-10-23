#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "daemon_ingest.h"

int handle_hw_sync_sample(void *ctx, void *data, size_t len) {
    struct daemon_ctx *d = (struct daemon_ctx *)ctx;
    if (len < sizeof(struct hw_cache_sync_event)) return 0;

    const struct hw_cache_sync_event *evt = (const struct hw_cache_sync_event *)data;

    /* Ensure clean 56-byte zero-padded key */
    char key[MAX_DNS_NAME_LENGTH_HW] = {0};
    size_t nlen = 0;
    while (nlen < MAX_DNS_NAME_LENGTH_HW && evt->name[nlen] != 0) {
        key[nlen] = evt->name[nlen];
        nlen++;
    }
    if (nlen < MAX_DNS_NAME_LENGTH_HW) {
        key[nlen] = 0;
    }

    uint32_t now = (uint32_t)time(NULL);
    uint32_t hw_timestamp = evt->timestamp;

    /* If timestamp was generated via bpf_ktime_get_ns() (monotonic uptime),
     * convert to Unix epoch matching SmartNIC time_map */
    if (hw_timestamp < 1000000000U) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        uint32_t mono_now = (uint32_t)ts.tv_sec;
        uint32_t ttl = (hw_timestamp > mono_now) ? (hw_timestamp - mono_now) : 300;
        hw_timestamp = now + ttl;
    }

    struct a_record_hw rec = {
        .timestamp = hw_timestamp,
        .ip = evt->ip
    };

    uint32_t capacity = d->cfg.hw_cache_capacity ? d->cfg.hw_cache_capacity : DEFAULT_HW_CACHE_CAPACITY;
    if (d->wheel && d->wheel->total_entries >= capacity) {
        uint32_t count = 0;

        struct wheel_node *victim = timing_wheel_pop_expired(d->wheel, now, &count);
        if (!victim) {
            /* Hardware SRAM is full of valid (unexpired) hot entries; keep hot working set in SRAM */
            return 0;
        }
        while (victim) {
            struct wheel_node *next = victim->next;
            if (d->hw_cache_fd >= 0) {
                bpf_map_delete_elem(d->hw_cache_fd, victim->name);
            }
            free(victim);
            d->total_passive_evicted++;
            victim = next;
        }
    }

    if (d->wheel) {
        timing_wheel_insert(d->wheel, key, hw_timestamp);
    }

    /* 2. Write to SmartNIC level_one_cache via PCIe DMA (paced to prevent NFP CMSG ring timeout) */
    if (d->hw_cache_fd >= 0) {
        int ret = bpf_map_update_elem(d->hw_cache_fd, key, &rec, BPF_ANY);
        if (ret == 0) {
            d->total_ingested++;
            if ((d->total_ingested & 31) == 0) {
                usleep(1000);
            }
        }
    }

    return 0;
}

void *ingest_worker_thread(void *arg) {
    struct daemon_ctx *d = (struct daemon_ctx *)arg;
    pin_to_core(d->cfg.ingest_core);

    if (d->cfg.verbose)
        printf("[Ingest Worker] Thread started on core %d (Lockless Ingestion)\n", d->cfg.ingest_core);

    while (d->running) {
        if (!d->rb) {
            if (d->ringbuf_map_fd < 0) {
                d->ringbuf_map_fd = bpf_obj_get(d->cfg.ringbuf_path);
            }
            if (d->ringbuf_map_fd >= 0) {
                d->rb = ring_buffer__new(d->ringbuf_map_fd, handle_hw_sync_sample, d, NULL);
                if (d->rb && d->cfg.verbose) {
                    printf("[Ingest Worker] Connected to ring buffer '%s'\n", d->cfg.ringbuf_path);
                }
            }
            if (!d->rb) {
                sleep(1);
                continue;
            }
        }

        int err = ring_buffer__poll(d->rb, 50 /* timeout_ms */);
        if (err < 0 && err != -EINTR) {
            if (d->cfg.verbose)
                fprintf(stderr, "[Ingest Worker] Ring buffer poll returned %d. Reconnecting...\n", err);
            ring_buffer__free(d->rb);
            d->rb = NULL;
            if (d->ringbuf_map_fd >= 0) {
                close(d->ringbuf_map_fd);
                d->ringbuf_map_fd = -1;
            }
            sleep(1);
        }
    }

    if (d->rb) {
        ring_buffer__free(d->rb);
        d->rb = NULL;
    }

    if (d->cfg.verbose)
        printf("[Ingest Worker] Exiting...\n");
    return NULL;
}
