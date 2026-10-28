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

    uint64_t timer_ticks = 0;

    while (d->running) {
        ssize_t s = read(tfd, &timer_ticks, sizeof(timer_ticks));
        if (s <= 0 || !d->running) break;

        uint32_t now = (uint32_t)time(NULL);

        /* Synchronize Hardware Clock (time_map) at 1 Hz via single 4-byte PCIe DMA write */
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

        if (d->cfg.verbose && (timer_ticks % 10 == 0)) {
            uint64_t occ = d->wheel ? d->wheel->total_entries : 0;
            printf("[Governance 1Hz] Clock Synced (now=%u) | Cache Occ: %lu/%u | Passive Evictions: %lu\n",
                   now, occ, d->cfg.hw_cache_capacity, d->total_passive_evicted);
        }
    }

    close(tfd);
    if (d->cfg.verbose)
        printf("[Governance Worker] Exiting...\n");
    return NULL;
}
