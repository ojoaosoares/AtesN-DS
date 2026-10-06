/**
 * @file atesnds_daemon.c
 * @brief Unified Multithreaded Control-Plane Runtime for AtesN-DS
 *
 * Coordinates:
 * 1. Asymmetric Cache Ingestion (Thread 1 - Core 1):
 *    Consumes verified DNS resolution events from host driver (XDP) via BPF Ring Buffer
 *    and populates SmartNIC level_one_cache over PCIe DMA.
 * 2. Governance & Proactive Eviction (Thread 2 - Core 2):
 *    1 Hz timer synchronization to SmartNIC time_map, zero-PCIe-read local DRAM
 *    Timing Wheel expiration, and dual-watermark proactive eviction.
 * 3. Authoritative Resolver & Prefetching (Thread 3 - Core 3):
 *    Asynchronous upstream queries and error prevention handling.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <errno.h>

#include "daemon_context.h"
#include "daemon_timing_wheel.h"
#include "daemon_ingest.h"
#include "daemon_cleaner.h"
#include "daemon_prefetch.h"

static struct daemon_ctx g_ctx;

static void sig_handler(int sig) {
    (void)sig;
    g_ctx.running = false;
}

static void print_usage(const char *prog) {
    printf("AtesN-DS Unified Control-Plane Runtime (Multithreaded)\n");
    printf("Usage: sudo %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  -c, --cache <path>        Path to pinned SmartNIC level_one_cache (default: %s)\n", DEFAULT_HW_CACHE_PATH);
    printf("  -t, --time-map <path>     Path to pinned SmartNIC time_map (default: %s)\n", DEFAULT_TIME_MAP_PATH);
    printf("  -r, --ringbuf <path>      Path to pinned host hw_sync_ringbuf (default: %s)\n", DEFAULT_RINGBUF_PATH);
    printf("  -n, --capacity <entries>  SmartNIC hardware cache capacity (default: 2000000)\n");
    printf("  -H, --high-watermark <%%>  High watermark percentage for eviction (default: 90)\n");
    printf("  -L, --low-watermark <%%>   Low watermark percentage target (default: 80)\n");
    printf("  --ingest-core <id>        CPU Core for Ingestion Worker (default: 1)\n");
    printf("  --gov-core <id>           CPU Core for Governance Worker (default: 2)\n");
    printf("  -v, --verbose             Enable detailed operational metrics\n");
    printf("  -h, --help                Show this help message\n");
}

int main(int argc, char *argv[]) {
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    memset(&g_ctx, 0, sizeof(g_ctx));
    strncpy(g_ctx.cfg.hw_cache_path, DEFAULT_HW_CACHE_PATH, sizeof(g_ctx.cfg.hw_cache_path)-1);
    strncpy(g_ctx.cfg.time_map_path, DEFAULT_TIME_MAP_PATH, sizeof(g_ctx.cfg.time_map_path)-1);
    strncpy(g_ctx.cfg.ringbuf_path, DEFAULT_RINGBUF_PATH, sizeof(g_ctx.cfg.ringbuf_path)-1);
    strncpy(g_ctx.cfg.resolver_ringbuf_path, "/sys/fs/bpf/ringbuf_send_packet", sizeof(g_ctx.cfg.resolver_ringbuf_path)-1);
    g_ctx.cfg.hw_cache_capacity = 2000000;
    g_ctx.cfg.high_watermark_pct = 90;
    g_ctx.cfg.low_watermark_pct = 80;
    g_ctx.cfg.ingest_core = 1;
    g_ctx.cfg.governance_core = 2;
    g_ctx.cfg.resolver_core = 3;
    g_ctx.cfg.verbose = false;

    static struct option long_opts[] = {
        {"cache", required_argument, 0, 'c'},
        {"time-map", required_argument, 0, 't'},
        {"ringbuf", required_argument, 0, 'r'},
        {"capacity", required_argument, 0, 'n'},
        {"high-watermark", required_argument, 0, 'H'},
        {"low-watermark", required_argument, 0, 'L'},
        {"ingest-core", required_argument, 0, 1001},
        {"gov-core", required_argument, 0, 1002},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "c:t:r:n:H:L:vh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'c': strncpy(g_ctx.cfg.hw_cache_path, optarg, sizeof(g_ctx.cfg.hw_cache_path)-1); break;
        case 't': strncpy(g_ctx.cfg.time_map_path, optarg, sizeof(g_ctx.cfg.time_map_path)-1); break;
        case 'r': strncpy(g_ctx.cfg.ringbuf_path, optarg, sizeof(g_ctx.cfg.ringbuf_path)-1); break;
        case 'n': g_ctx.cfg.hw_cache_capacity = atoi(optarg); break;
        case 'H': g_ctx.cfg.high_watermark_pct = atoi(optarg); break;
        case 'L': g_ctx.cfg.low_watermark_pct = atoi(optarg); break;
        case 1001: g_ctx.cfg.ingest_core = atoi(optarg); break;
        case 1002: g_ctx.cfg.governance_core = atoi(optarg); break;
        case 'v': g_ctx.cfg.verbose = true; break;
        case 'h': print_usage(argv[0]); return 0;
        default:  print_usage(argv[0]); return 1;
        }
    }

    if (g_ctx.cfg.verbose) {
        printf("======================================================================\n");
        printf("  🚀 Starting AtesN-DS Unified Control-Plane Runtime (Modular)        \n");
        printf("======================================================================\n");
        printf("  SmartNIC Cache Pin: %s\n", g_ctx.cfg.hw_cache_path);
        printf("  SmartNIC Time Pin:  %s\n", g_ctx.cfg.time_map_path);
        printf("  Host RingBuf Pin:   %s\n", g_ctx.cfg.ringbuf_path);
        printf("  Hardware Capacity:  %u entries (High=%u%%, Low=%u%%)\n",
               g_ctx.cfg.hw_cache_capacity, g_ctx.cfg.high_watermark_pct, g_ctx.cfg.low_watermark_pct);
        printf("  Core Assignment:    Ingest=Core %d, Governance=Core %d (Core 0 Network Isolated)\n",
               g_ctx.cfg.ingest_core, g_ctx.cfg.governance_core);
        printf("======================================================================\n");
    }

    /* Open SmartNIC BPF Maps */
    g_ctx.hw_cache_fd = bpf_obj_get(g_ctx.cfg.hw_cache_path);
    if (g_ctx.hw_cache_fd < 0) {
        fprintf(stderr, "[ERROR] Could not open SmartNIC cache map at '%s': %s\n",
                g_ctx.cfg.hw_cache_path, strerror(errno));
        fprintf(stderr, "Ensure 'make load-hw' is executed before launching runtime.\n");
        return 1;
    }

    g_ctx.time_map_fd = bpf_obj_get(g_ctx.cfg.time_map_path);
    if (g_ctx.time_map_fd < 0) {
        fprintf(stderr, "[ERROR] Could not open SmartNIC time map at '%s': %s\n",
                g_ctx.cfg.time_map_path, strerror(errno));
        close(g_ctx.hw_cache_fd);
        return 1;
    }

    g_ctx.ringbuf_map_fd = bpf_obj_get(g_ctx.cfg.ringbuf_path);
    if (g_ctx.ringbuf_map_fd < 0) {
        fprintf(stderr, "[WARN] Host ring buffer map not pinned at '%s'. Standalone mode.\n",
                g_ctx.cfg.ringbuf_path);
    }

    /* Initialize Host DRAM Timing Wheel */
    g_ctx.wheel = timing_wheel_create(WHEEL_SECONDS_CAPACITY);
    if (!g_ctx.wheel) {
        fprintf(stderr, "[FATAL] Failed to allocate Host DRAM Timing Wheel.\n");
        close(g_ctx.hw_cache_fd);
        close(g_ctx.time_map_fd);
        return 1;
    }

    /* Create Ring Buffer Consumer */
    if (g_ctx.ringbuf_map_fd >= 0) {
        g_ctx.rb = ring_buffer__new(g_ctx.ringbuf_map_fd, handle_hw_sync_sample, &g_ctx, NULL);
        if (!g_ctx.rb) {
            fprintf(stderr, "[ERROR] Failed to initialize ring buffer consumer.\n");
            timing_wheel_destroy(g_ctx.wheel);
            close(g_ctx.hw_cache_fd);
            close(g_ctx.time_map_fd);
            return 1;
        }
    }

    /* Optional: Open Resolver Ring Buffer */
    g_ctx.resolver_ringbuf_fd = bpf_obj_get(g_ctx.cfg.resolver_ringbuf_path);
    if (g_ctx.resolver_ringbuf_fd >= 0) {
        g_ctx.rb_resolver = ring_buffer__new(g_ctx.resolver_ringbuf_fd, handle_resolver_sample, &g_ctx, NULL);
    }

    g_ctx.running = true;

    pthread_t ingest_tid, gov_tid, resolver_tid;
    bool has_resolver_thread = false;

    /* Launch Thread 2: Governance & Cleaner Worker (Core 2) */
    if (pthread_create(&gov_tid, NULL, governance_worker_thread, &g_ctx) != 0) {
        perror("pthread_create (governance)");
        g_ctx.running = false;
    }

    /* Launch Thread 1: Ingestion Worker (Core 1) */
    bool has_ingest_thread = false;
    if (pthread_create(&ingest_tid, NULL, ingest_worker_thread, &g_ctx) == 0) {
        has_ingest_thread = true;
    } else {
        perror("pthread_create (ingestion)");
    }

    /* Launch Thread 3: Prefetch & Resolver Worker (Core 3, if resolver ringbuf available) */
    if (g_ctx.rb_resolver) {
        if (pthread_create(&resolver_tid, NULL, resolver_worker_thread, &g_ctx) == 0) {
            has_resolver_thread = true;
        }
    }

    if (g_ctx.cfg.verbose) {
        printf("  ✅ AtesN-DS Unified Control-Plane Runtime is active.\n");
        printf("  Press Ctrl+C to terminate.\n\n");
    }

    /* Main coordination loop: log summary every 10 seconds if verbose */
    while (g_ctx.running) {
        sleep(10);
        if (g_ctx.running && g_ctx.cfg.verbose) {
            printf("[AtesN-DS Status] Ingested: %lu | Passive Evicted (On-Write): %lu | Occupancy: %lu/%u (Zero-PCIe-Reads)\n",
                   g_ctx.total_ingested, g_ctx.total_passive_evicted, g_ctx.wheel->total_entries, g_ctx.cfg.hw_cache_capacity);
        }
    }

    printf("\nShutting down AtesN-DS Unified Control-Plane Runtime...\n");
    pthread_join(gov_tid, NULL);
    if (has_ingest_thread) {
        pthread_join(ingest_tid, NULL);
    }
    if (has_resolver_thread) {
        pthread_join(resolver_tid, NULL);
        ring_buffer__free(g_ctx.rb_resolver);
    }

    timing_wheel_destroy(g_ctx.wheel);
    close(g_ctx.hw_cache_fd);
    close(g_ctx.time_map_fd);
    if (g_ctx.ringbuf_map_fd >= 0) close(g_ctx.ringbuf_map_fd);
    if (g_ctx.resolver_ringbuf_fd >= 0) close(g_ctx.resolver_ringbuf_fd);

    printf("Graceful shutdown complete.\n");
    return 0;
}
