// SPDX-License-Identifier: GPL-2.0
/*
 * cleaner_daemon.c — High-performance Userspace Cleaner & Eviction Daemon
 * for AtesN-DS offloaded eBPF L1 hardware DNS cache (level_one_cache).
 *
 * Responsibilities:
 * 1. Periodically scans the offloaded hash map (level_one_cache) in bounded batches.
 * 2. Reclaims expired records (TTL expiration: arecord.timestamp <= current_time).
 * 3. Enforces LRU / Min-TTL eviction when table capacity exceeds HIGH_WATERMARK (e.g. 90%),
 *    preventing hash map saturation and ensuring continuous cache learning.
 * 4. Paces memory transactions (microsecond batch yields) to ensure zero interference
 *    with the SmartNIC packet processing datapath (< 0.1% PCIe bandwidth, < 1% CPU core).
 * 5. Logs CPU consumption, map access rates, and eviction statistics.
 */

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "dns.h"

#define DEFAULT_PIN_PATH         "/sys/fs/bpf/level_one_cache"
#define DEFAULT_MAP_NAME         "level_one_cache"
#define DEFAULT_SCAN_INTERVAL_SEC 15
#define DEFAULT_BATCH_SIZE       256
#define DEFAULT_BATCH_SLEEP_US   1500
#define DEFAULT_HIGH_WATERMARK   90
#define DEFAULT_LOW_WATERMARK    80
#define MAX_EVICT_CANDIDATES     4096

struct eviction_candidate {
    char key[MAX_DNS_NAME_LENGTH_HW];
    uint32_t remaining_ttl;
};

struct cleaner_config {
    const char *pin_path;
    const char *csv_output;
    uint32_t scan_interval_sec;
    uint32_t batch_size;
    uint32_t batch_sleep_us;
    uint32_t high_watermark_pct;
    uint32_t low_watermark_pct;
    bool verbose;
    bool benchmark_once;
};

struct cleaner_stats {
    uint64_t total_scans;
    uint64_t entries_scanned;
    uint64_t expired_deleted;
    uint64_t lru_evicted;
    double scan_duration_ms;
    double cpu_utilization_pct;
    double map_access_rate_qps;
    double pcie_bandwidth_mb_s;
};

static volatile int running = 1;

static void handle_signal(int sig)
{
    (void)sig;
    running = 0;
}

static int open_hw_map(const char *pin_path)
{
    int fd = bpf_obj_get(pin_path);
    if (fd >= 0)
        return fd;

    /* Fallback: search by BPF map name */
    uint32_t id = 0;
    while (bpf_map_get_next_id(id, &id) == 0) {
        int candidate_fd = bpf_map_get_fd_by_id(id);
        if (candidate_fd < 0)
            continue;

        struct bpf_map_info info = {0};
        uint32_t len = sizeof(info);
        if (bpf_obj_get_info_by_fd(candidate_fd, &info, &len) == 0) {
            if (strcmp(info.name, DEFAULT_MAP_NAME) == 0)
                return candidate_fd;
        }
        close(candidate_fd);
    }

    return -1;
}

static uint32_t get_unix_now(void)
{
    time_t t = time(NULL);
    return (t == (time_t)-1) ? 0 : (uint32_t)t;
}

static void candidate_insert(struct eviction_candidate *candidates, size_t *count, size_t max_count,
                             const char *key, uint32_t remaining_ttl)
{
    if (*count < max_count) {
        memcpy(candidates[*count].key, key, MAX_DNS_NAME_LENGTH_HW);
        candidates[*count].remaining_ttl = remaining_ttl;
        (*count)++;
    }
}

static int cmp_candidate_ttl(const void *a, const void *b)
{
    const struct eviction_candidate *ca = a;
    const struct eviction_candidate *cb = b;
    if (ca->remaining_ttl < cb->remaining_ttl)
        return -1;
    if (ca->remaining_ttl > cb->remaining_ttl)
        return 1;
    return 0;
}

static int perform_cleaner_sweep(int map_fd, const struct cleaner_config *cfg,
                                struct cleaner_stats *stats, uint32_t max_entries)
{
    struct timespec start_ts, end_ts;
    struct rusage start_ru, end_ru;

    clock_gettime(CLOCK_MONOTONIC, &start_ts);
    getrusage(RUSAGE_SELF, &start_ru);

    char key[MAX_DNS_NAME_LENGTH_HW] = {0};
    char next_key[MAX_DNS_NAME_LENGTH_HW] = {0};
    struct a_record_hw val = {0};

    uint32_t now = get_unix_now();
    uint64_t total_entries = 0;
    uint64_t expired_deleted = 0;
    uint64_t lru_evicted = 0;

    struct eviction_candidate *candidates = malloc(sizeof(*candidates) * MAX_EVICT_CANDIDATES);
    size_t candidate_count = 0;

    uint32_t batch_count = 0;

    char cur_key[MAX_DNS_NAME_LENGTH_HW] = {0};

    /* Start traversal from NULL key */
    int res = bpf_map_get_next_key(map_fd, NULL, next_key);
    while (res == 0 && running) {
        total_entries++;
        batch_count++;

        memcpy(cur_key, next_key, sizeof(cur_key));
        /* Advance iterator to next_key BEFORE deleting cur_key */
        res = bpf_map_get_next_key(map_fd, cur_key, next_key);

        if (bpf_map_lookup_elem(map_fd, cur_key, &val) == 0) {
            if (val.timestamp <= now) {
                /* TTL Expired -> Zero-loss reclamation */
                if (bpf_map_delete_elem(map_fd, cur_key) == 0)
                    expired_deleted++;
            } else if (candidates && candidate_count < MAX_EVICT_CANDIDATES) {
                uint32_t remaining = val.timestamp - now;
                candidate_insert(candidates, &candidate_count, MAX_EVICT_CANDIDATES, cur_key, remaining);
            }
        }

        /* Rate limiting: yield CPU and PCIe bus every batch_size lookups */
        if (batch_count >= cfg->batch_size) {
            batch_count = 0;
            if (cfg->batch_sleep_us > 0)
                usleep(cfg->batch_sleep_us);
        }
    }

    uint64_t live_entries = (total_entries > expired_deleted) ? (total_entries - expired_deleted) : 0;
    uint64_t high_watermark_entries = ((uint64_t)max_entries * cfg->high_watermark_pct) / 100;
    uint64_t low_watermark_entries  = ((uint64_t)max_entries * cfg->low_watermark_pct) / 100;

    /* Phase 2: Watermark-driven LRU/Min-TTL Eviction if capacity exceeded */
    if (live_entries > high_watermark_entries && candidates && candidate_count > 0) {
        uint64_t to_evict = live_entries - low_watermark_entries;
        if (to_evict > candidate_count)
            to_evict = candidate_count;

        qsort(candidates, candidate_count, sizeof(*candidates), cmp_candidate_ttl);

        for (size_t i = 0; i < to_evict; i++) {
            if (bpf_map_delete_elem(map_fd, candidates[i].key) == 0) {
                lru_evicted++;
                live_entries--;
            }
        }
    }

    free(candidates);

    clock_gettime(CLOCK_MONOTONIC, &end_ts);
    getrusage(RUSAGE_SELF, &end_ru);

    double elapsed_sec = (end_ts.tv_sec - start_ts.tv_sec) +
                         (end_ts.tv_nsec - start_ts.tv_nsec) / 1e9;
    if (elapsed_sec <= 0.0)
        elapsed_sec = 1e-6;

    double user_cpu = (end_ru.ru_utime.tv_sec - start_ru.ru_utime.tv_sec) +
                      (end_ru.ru_utime.tv_usec - start_ru.ru_utime.tv_usec) / 1e6;
    double sys_cpu  = (end_ru.ru_stime.tv_sec - start_ru.ru_stime.tv_sec) +
                      (end_ru.ru_stime.tv_usec - start_ru.ru_stime.tv_usec) / 1e6;
    double cpu_pct = ((user_cpu + sys_cpu) / elapsed_sec) * 100.0;

    stats->total_scans++;
    stats->entries_scanned = total_entries;
    stats->expired_deleted = expired_deleted;
    stats->lru_evicted = lru_evicted;
    stats->scan_duration_ms = elapsed_sec * 1000.0;
    stats->cpu_utilization_pct = cpu_pct;
    stats->map_access_rate_qps = (double)total_entries / elapsed_sec;
    /* PCIe payload per lookup: key (38B) + value (8B) + control header (~16B) = ~62B */
    stats->pcie_bandwidth_mb_s = (stats->map_access_rate_qps * 62.0) / (1024.0 * 1024.0);

    return 0;
}

static void print_help(const char *prog)
{
    printf("Usage: %s [options]\n", prog);
    printf("Options:\n");
    printf("  -p, --pin-path PATH      Path to pinned BPF map (default: %s)\n", DEFAULT_PIN_PATH);
    printf("  -i, --interval SEC       Sweep interval in seconds (default: %u)\n", DEFAULT_SCAN_INTERVAL_SEC);
    printf("  -b, --batch SIZE         Batch size before yielding (default: %u)\n", DEFAULT_BATCH_SIZE);
    printf("  -s, --sleep USEC         Microseconds to sleep per batch (default: %u)\n", DEFAULT_BATCH_SLEEP_US);
    printf("  -H, --high-watermark PCT High watermark %% to trigger LRU eviction (default: %u)\n", DEFAULT_HIGH_WATERMARK);
    printf("  -L, --low-watermark PCT  Low watermark %% target after eviction (default: %u)\n", DEFAULT_LOW_WATERMARK);
    printf("  -o, --output FILE        Write sweep measurements to CSV file\n");
    printf("  -B, --benchmark          Execute a single sweep and print detailed metrics\n");
    printf("  -v, --verbose            Print per-sweep statistics to stdout\n");
    printf("  -h, --help               Show this help message\n");
}

int main(int argc, char *argv[])
{
    struct cleaner_config cfg = {
        .pin_path = DEFAULT_PIN_PATH,
        .csv_output = NULL,
        .scan_interval_sec = DEFAULT_SCAN_INTERVAL_SEC,
        .batch_size = DEFAULT_BATCH_SIZE,
        .batch_sleep_us = DEFAULT_BATCH_SLEEP_US,
        .high_watermark_pct = DEFAULT_HIGH_WATERMARK,
        .low_watermark_pct = DEFAULT_LOW_WATERMARK,
        .verbose = false,
        .benchmark_once = false,
    };

    static struct option long_opts[] = {
        {"pin-path",        required_argument, 0, 'p'},
        {"interval",        required_argument, 0, 'i'},
        {"batch",           required_argument, 0, 'b'},
        {"sleep",           required_argument, 0, 's'},
        {"high-watermark",  required_argument, 0, 'H'},
        {"low-watermark",   required_argument, 0, 'L'},
        {"output",          required_argument, 0, 'o'},
        {"benchmark",       no_argument,       0, 'B'},
        {"verbose",         no_argument,       0, 'v'},
        {"help",            no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "p:i:b:s:H:L:o:Bvh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'p': cfg.pin_path = optarg; break;
        case 'i': cfg.scan_interval_sec = (uint32_t)atoi(optarg); break;
        case 'b': cfg.batch_size = (uint32_t)atoi(optarg); break;
        case 's': cfg.batch_sleep_us = (uint32_t)atoi(optarg); break;
        case 'H': cfg.high_watermark_pct = (uint32_t)atoi(optarg); break;
        case 'L': cfg.low_watermark_pct = (uint32_t)atoi(optarg); break;
        case 'o': cfg.csv_output = optarg; break;
        case 'B': cfg.benchmark_once = true; break;
        case 'v': cfg.verbose = true; break;
        case 'h': print_help(argv[0]); return EXIT_SUCCESS;
        default:  print_help(argv[0]); return EXIT_FAILURE;
        }
    }

    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    printf("[cleaner_daemon] Initializing with map '%s'...\n", cfg.pin_path);
    int map_fd = open_hw_map(cfg.pin_path);
    if (map_fd < 0) {
        fprintf(stderr, "[cleaner_daemon] Error: Unable to access map '%s'.\n", cfg.pin_path);
        fprintf(stderr, "  Ensure XDP hardware program is loaded and map is pinned:\n");
        fprintf(stderr, "    sudo bpftool map pin id <ID> %s\n", cfg.pin_path);
        return EXIT_FAILURE;
    }

    struct bpf_map_info info = {0};
    uint32_t info_len = sizeof(info);
    uint32_t max_entries = 2000000;
    if (bpf_obj_get_info_by_fd(map_fd, &info, &info_len) == 0) {
        max_entries = info.max_entries;
        printf("[cleaner_daemon] Map detected: name='%s', key=%uB, val=%uB, max_entries=%u\n",
               info.name, info.key_size, info.value_size, info.max_entries);
    }

    FILE *csv_fp = NULL;
    if (cfg.csv_output) {
        csv_fp = fopen(cfg.csv_output, "w");
        if (csv_fp) {
            fprintf(csv_fp, "sweep,entries_scanned,expired_deleted,lru_evicted,duration_ms,cpu_pct,access_rate_qps,pcie_mb_s\n");
            fflush(csv_fp);
        }
    }

    printf("[cleaner_daemon] Running (interval=%us, batch=%u, sleep=%uus, high_wm=%u%%, low_wm=%u%%)...\n",
           cfg.scan_interval_sec, cfg.batch_size, cfg.batch_sleep_us,
           cfg.high_watermark_pct, cfg.low_watermark_pct);

    struct cleaner_stats stats = {0};

    while (running) {
        perform_cleaner_sweep(map_fd, &cfg, &stats, max_entries);

        if (cfg.verbose || cfg.benchmark_once) {
            printf("[sweep #%lu] Scanned: %lu, Expired: %lu, LRU Evicted: %lu | "
                   "Duration: %.2f ms, CPU: %.2f%%, Rate: %.0f lookups/s, PCIe: %.2f MB/s\n",
                   stats.total_scans, stats.entries_scanned, stats.expired_deleted, stats.lru_evicted,
                   stats.scan_duration_ms, stats.cpu_utilization_pct,
                   stats.map_access_rate_qps, stats.pcie_bandwidth_mb_s);
        }

        if (csv_fp) {
            fprintf(csv_fp, "%lu,%lu,%lu,%lu,%.2f,%.2f,%.0f,%.2f\n",
                    stats.total_scans, stats.entries_scanned, stats.expired_deleted, stats.lru_evicted,
                    stats.scan_duration_ms, stats.cpu_utilization_pct,
                    stats.map_access_rate_qps, stats.pcie_bandwidth_mb_s);
            fflush(csv_fp);
        }

        if (cfg.benchmark_once)
            break;

        /* Sleep until next sweep interval */
        for (uint32_t s = 0; s < cfg.scan_interval_sec && running; s++)
            sleep(1);
    }

    if (csv_fp)
        fclose(csv_fp);
    close(map_fd);

    printf("[cleaner_daemon] Terminated cleanly. Total sweeps: %lu, Expired: %lu, LRU Evicted: %lu.\n",
           stats.total_scans, stats.expired_deleted, stats.lru_evicted);

    return EXIT_SUCCESS;
}
