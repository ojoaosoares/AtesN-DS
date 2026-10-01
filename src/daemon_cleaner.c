#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/timerfd.h>
#include "daemon_cleaner.h"

void *governance_worker_thread(void *arg) {
    struct daemon_ctx *d = (struct daemon_ctx *)arg;
    pin_to_core(d->cfg.governance_core);

    if (d->cfg.verbose)
        printf("[Governance Worker] Thread started on core %d (1 Hz Clock & Proactive Eviction)\n", d->cfg.governance_core);

    int tfd = timerfd_create(CLOCK_MONOTONIC, 0);
    if (tfd < 0) {
        perror("timerfd_create");
        return NULL;
    }

    struct itimerspec ts = {
        .it_interval = { .tv_sec = 1, .tv_nsec = 0 },
        .it_value    = { .tv_sec = 1, .tv_nsec = 0 }
    };

    if (timerfd_settime(tfd, 0, &ts, NULL) < 0) {
        perror("timerfd_settime");
        close(tfd);
        return NULL;
    }

    uint64_t expirations = 0;
    uint32_t high_watermark = (d->cfg.hw_cache_capacity * d->cfg.high_watermark_pct) / 100;
    uint32_t low_watermark  = (d->cfg.hw_cache_capacity * d->cfg.low_watermark_pct) / 100;

    while (d->running) {
        ssize_t s = read(tfd, &expirations, sizeof(expirations));
        if (s <= 0 || !d->running) break;

        uint32_t now = (uint32_t)time(NULL);

        /* 1. Synchronize Hardware Clock (time_map) at 1 Hz */
        uint32_t zero_key = 0;
        if (d->time_map_fd >= 0) {
            if (bpf_map_update_elem(d->time_map_fd, &zero_key, &now, BPF_ANY) != 0) {
                close(d->time_map_fd);
                d->time_map_fd = bpf_obj_get(d->cfg.time_map_path);
                if (d->time_map_fd >= 0) {
                    bpf_map_update_elem(d->time_map_fd, &zero_key, &now, BPF_ANY);
                }
            }
        } else {
            d->time_map_fd = bpf_obj_get(d->cfg.time_map_path);
            if (d->time_map_fd >= 0) {
                bpf_map_update_elem(d->time_map_fd, &zero_key, &now, BPF_ANY);
            }
        }

        if (d->hw_cache_fd < 0) {
            d->hw_cache_fd = bpf_obj_get(d->cfg.hw_cache_path);
        }

        /* 2. Zero-PCIe-Read Expiration: Pop expired keys directly from DRAM */
        uint32_t expired_count = 0;
        uint32_t del_pacing = 0;
        struct wheel_node *exp_list = timing_wheel_pop_expired(d->wheel, now, &expired_count);
        while (exp_list) {
            struct wheel_node *next = exp_list->next;
            if (d->hw_cache_fd >= 0) {
                bpf_map_delete_elem(d->hw_cache_fd, exp_list->name);
            }
            free(exp_list);
            exp_list = next;
            d->total_expired_deleted++;
            if (++del_pacing % 256 == 0) usleep(100);
        }

        if (d->cfg.verbose && expired_count > 0) {
            printf("[Governance] Purged %u expired entries from SmartNIC (Zero-PCIe-Reads)\n", expired_count);
        }

        /* 3. Dual-Watermark Proactive Eviction */
        uint64_t current_occ = d->wheel->total_entries;
        if (current_occ > high_watermark) {
            uint32_t needed_evictions = (uint32_t)(current_occ - low_watermark);
            uint32_t lru_evicted = 0;
            del_pacing = 0;
            struct wheel_node *lru_list = timing_wheel_pop_min_ttl(d->wheel, now, needed_evictions, &lru_evicted);
            while (lru_list) {
                struct wheel_node *next = lru_list->next;
                bpf_map_delete_elem(d->hw_cache_fd, lru_list->name);
                free(lru_list);
                lru_list = next;
                d->total_lru_evicted++;
                if (++del_pacing % 256 == 0) usleep(100);
            }

            if (d->cfg.verbose) {
                printf("[Governance] Watermark Triggered: Occ=%lu (High=%u, Low=%u) -> Proactively evicted %u entries\n",
                       current_occ, high_watermark, low_watermark, lru_evicted);
            }
        }
    }

    close(tfd);
    if (d->cfg.verbose)
        printf("[Governance Worker] Exiting...\n");
    return NULL;
}
