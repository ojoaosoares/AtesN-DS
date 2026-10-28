#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "dns.h"

#define DEFAULT_HW_CACHE_PIN     "/sys/fs/bpf/level_one_cache"
#define DEFAULT_TIME_MAP_PIN     "/sys/fs/bpf/time_map"
#define DEFAULT_DRIVER_CACHE_PIN "/sys/fs/bpf/cache_arecords"
#define DEFAULT_HW_TRACE_FILE    "tests/isp_top32k_hw_warmup_dnsperf.txt"
#define DEFAULT_HOST_TRACE_FILE  "tests/isp_unique_warmup_dnsperf.txt"
#define DEFAULT_TTL              3600

/* FNV-1a 32-bit hash function matching mock_dns_server.c */
static uint32_t hash_domain_name(const char *domain) {
    uint32_t hash = 2166136261u;
    const char *p = domain;
    while (*p && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n') {
        const char *dot = strchr(p, '.');
        size_t label_len = dot ? (size_t)(dot - p) : strlen(p);
        if (dot == NULL) {
            label_len = 0;
            while (p[label_len] && p[label_len] != ' ' && p[label_len] != '\t' && p[label_len] != '\r' && p[label_len] != '\n') {
                label_len++;
            }
        }
        if (label_len == 0) {
            if (dot) { p = dot + 1; continue; }
            break;
        }
        for (size_t i = 0; i < label_len; i++) {
            uint8_t c = (uint8_t)p[i];
            if (c >= 'A' && c <= 'Z') c += ('a' - 'A');
            hash ^= c;
            hash *= 16777619u;
        }
        hash ^= '.';
        hash *= 16777619u;
        if (dot) p = dot + 1;
        else p += label_len;
    }
    return hash;
}

/* Deterministic IPv4 matching mock_dns_server.c: 10.b2.b3.b4 */
static uint32_t get_synthetic_ip(uint32_t hash) {
    uint8_t b1 = 10;
    uint8_t b2 = (uint8_t)((hash >> 16) & 0xfe) | 1;
    uint8_t b3 = (uint8_t)((hash >> 8) & 0xfe) | 1;
    uint8_t b4 = (uint8_t)(hash & 0xfe) | 1;
    uint32_t ip;
    uint8_t *b = (uint8_t *)&ip;
    b[0] = b1;
    b[1] = b2;
    b[2] = b3;
    b[3] = b4;
    return ip;
}

/* Convert domain string (e.g. "www.google.com") into DNS wire format labels: \x03www\x06google\x03com\x00 */
static int domain_to_wire(const char *name, uint8_t *wire, size_t max_len) {
    size_t out_idx = 0;
    const char *p = name;
    while (*p == ' ' || *p == '\t') p++;

    while (*p && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n') {
        const char *dot = strchr(p, '.');
        size_t label_len = dot ? (size_t)(dot - p) : 0;
        if (dot == NULL) {
            label_len = 0;
            while (p[label_len] && p[label_len] != ' ' && p[label_len] != '\t' && p[label_len] != '\r' && p[label_len] != '\n') {
                label_len++;
            }
        }
        if (label_len == 0) {
            if (dot) { p = dot + 1; continue; }
            break;
        }
        if (label_len > 63 || out_idx + 1 + label_len >= max_len) {
            return -1;
        }
        wire[out_idx++] = (uint8_t)label_len;
        for (size_t i = 0; i < label_len; i++) {
            uint8_t c = (uint8_t)p[i];
            if (c >= 'A' && c <= 'Z') c += ('a' - 'A');
            wire[out_idx++] = c;
        }
        if (dot) p = dot + 1;
        else p += label_len;
    }
    if (out_idx >= max_len) return -1;
    wire[out_idx] = 0;
    return (int)out_idx;
}

/* Get map FD by pinned path, or search loaded maps by name if unpinned */
static int get_map_fd(const char *pin_path, const char *map_name) {
    int fd = bpf_obj_get(pin_path);
    if (fd >= 0) return fd;

    uint32_t id = 0;
    while (bpf_map_get_next_id(id, &id) == 0) {
        int mfd = bpf_map_get_fd_by_id(id);
        if (mfd < 0) continue;
        struct bpf_map_info info;
        uint32_t info_len = sizeof(info);
        memset(&info, 0, sizeof(info));
        if (bpf_obj_get_info_by_fd(mfd, &info, &info_len) == 0) {
            if (strcmp(info.name, map_name) == 0) {
                bpf_obj_pin(mfd, pin_path);
                return mfd;
            }
        }
        close(mfd);
    }
    return -1;
}

static int preload_hw(const char *trace_file, uint32_t ttl) {
    printf("[PRELOAD HW] Populating SmartNIC SRAM cache (%s)...\n", DEFAULT_HW_CACHE_PIN);
    int hw_fd = get_map_fd(DEFAULT_HW_CACHE_PIN, "level_one_cache");
    if (hw_fd < 0) {
        fprintf(stderr, "   [ERROR] Cannot open SmartNIC map '%s': %s\n", DEFAULT_HW_CACHE_PIN, strerror(errno));
        return -1;
    }

    int time_fd = get_map_fd(DEFAULT_TIME_MAP_PIN, "time_map");
    uint32_t now = (uint32_t)time(NULL);
    if (time_fd >= 0) {
        uint32_t key0 = 0;
        bpf_map_update_elem(time_fd, &key0, &now, BPF_ANY);
        close(time_fd);
    }

    FILE *f = fopen(trace_file, "r");
    if (!f) {
        fprintf(stderr, "   [ERROR] Cannot open trace file '%s': %s\n", trace_file, strerror(errno));
        close(hw_fd);
        return -1;
    }

    char line[512];
    uint32_t loaded = 0;
    uint32_t skipped = 0;
    struct timespec t_start, t_end;
    clock_gettime(CLOCK_MONOTONIC, &t_start);

    while (fgets(line, sizeof(line), f)) {
        char domain[256] = {0};
        uint32_t file_ttl = ttl;
        int n_parsed = sscanf(line, "%255s %u", domain, &file_ttl);
        if (n_parsed < 1) continue;

        uint8_t wire[MAX_DNS_NAME_LENGTH_HW];
        memset(wire, 0, sizeof(wire));
        int wlen = domain_to_wire(domain, wire, sizeof(wire));
        if (wlen < 0) {
            skipped++;
            continue;
        }

        uint32_t h = hash_domain_name(domain);
        uint32_t ip = get_synthetic_ip(h);
        uint32_t entry_ttl = (n_parsed >= 2) ? file_ttl : ((ttl >= 5) ? (ttl - 2 + (h % 5)) : ttl);

        struct a_record_hw rec = {
            .timestamp = now + entry_ttl,
            .ip = ip
        };

        if (bpf_map_update_elem(hw_fd, wire, &rec, BPF_ANY) == 0) {
            loaded++;
            /* Pace PCIe DMA writes to avoid Netronome CMSG ring overflow: 1ms every 16 writes */
            if ((loaded & 15) == 0) {
                usleep(1000);
            }
        } else {
            skipped++;
        }
    }
    fclose(f);
    close(hw_fd);

    clock_gettime(CLOCK_MONOTONIC, &t_end);
    double elapsed_ms = (t_end.tv_sec - t_start.tv_sec) * 1000.0 + (t_end.tv_nsec - t_start.tv_nsec) / 1000000.0;
    printf("   ✓ [PRELOAD HW] Loaded %u domains (skipped %u) into SmartNIC SRAM in %.1f ms (TTL=%us)\n",
           loaded, skipped, elapsed_ms, ttl);
    return 0;
}

static int preload_driver(const char *trace_file, uint32_t ttl) {
    printf("[PRELOAD DRIVER] Populating Driver DRAM cache (%s)...\n", DEFAULT_DRIVER_CACHE_PIN);
    int drv_fd = get_map_fd(DEFAULT_DRIVER_CACHE_PIN, "cache_arecords");
    if (drv_fd < 0) {
        fprintf(stderr, "   [ERROR] Cannot open driver cache map '%s': %s\n", DEFAULT_DRIVER_CACHE_PIN, strerror(errno));
        return -1;
    }

    struct timespec mono_ts;
    clock_gettime(CLOCK_MONOTONIC, &mono_ts);
    uint64_t mono_now = (uint64_t)mono_ts.tv_sec;

    FILE *f = fopen(trace_file, "r");
    if (!f) {
        fprintf(stderr, "   [ERROR] Cannot open trace file '%s': %s\n", trace_file, strerror(errno));
        close(drv_fd);
        return -1;
    }

    char line[512];
    uint32_t loaded = 0;
    uint32_t skipped = 0;
    struct timespec t_start, t_end;
    clock_gettime(CLOCK_MONOTONIC, &t_start);

    while (fgets(line, sizeof(line), f)) {
        char domain[256] = {0};
        uint32_t file_ttl = ttl;
        int n_parsed = sscanf(line, "%255s %u", domain, &file_ttl);
        if (n_parsed < 1) continue;

        uint8_t wire[MAX_DNS_NAME_LENGTH_SW];
        memset(wire, 0, sizeof(wire));
        int wlen = domain_to_wire(domain, wire, sizeof(wire));
        if (wlen < 0) {
            skipped++;
            continue;
        }

        uint32_t h = hash_domain_name(domain);
        uint32_t ip = get_synthetic_ip(h);
        uint32_t entry_ttl = (n_parsed >= 2) ? file_ttl : ((ttl >= 5) ? (ttl - 2 + (h % 5)) : ttl);

        struct a_record_sw rec = {
            .timestamp = mono_now + entry_ttl,
            .ip = ip,
            .prefetch = 0
        };

        if (bpf_map_update_elem(drv_fd, wire, &rec, BPF_ANY) == 0) {
            loaded++;
        } else {
            skipped++;
        }
    }
    fclose(f);
    close(drv_fd);

    clock_gettime(CLOCK_MONOTONIC, &t_end);
    double elapsed_ms = (t_end.tv_sec - t_start.tv_sec) * 1000.0 + (t_end.tv_nsec - t_start.tv_nsec) / 1000000.0;
    printf("   ✓ [PRELOAD DRIVER] Loaded %u domains (skipped %u) into Driver DRAM in %.1f ms (TTL=%us)\n",
           loaded, skipped, elapsed_ms, ttl);
    return 0;
}

static int preload_unbound(const char *trace_file, uint32_t ttl) {
    printf("[PRELOAD UNBOUND] Populating Unbound user-space cache via unbound-control...\n");
    FILE *f = fopen(trace_file, "r");
    if (!f) {
        fprintf(stderr, "   [ERROR] Cannot open trace file '%s': %s\n", trace_file, strerror(errno));
        return -1;
    }

    /* Stream directly into unbound-control load_cache stdin */
    FILE *pipe = popen("sudo -n unbound-control load_cache >/dev/null 2>&1", "w");
    if (!pipe) {
        fprintf(stderr, "   [ERROR] Failed to execute 'unbound-control load_cache': %s\n", strerror(errno));
        fclose(f);
        return -1;
    }

    /* Allocate domain list buffer */
    size_t cap = 65536;
    char **domains = malloc(cap * sizeof(char *));
    uint32_t *hashes = malloc(cap * sizeof(uint32_t));
    uint32_t *ttls = malloc(cap * sizeof(uint32_t));
    uint32_t count = 0;

    char line[512];
    struct timespec t_start, t_end;
    clock_gettime(CLOCK_MONOTONIC, &t_start);

    while (fgets(line, sizeof(line), f)) {
        char d[256] = {0};
        uint32_t file_ttl = ttl;
        int n_parsed = sscanf(line, "%255s %u", d, &file_ttl);
        if (n_parsed < 1) continue;
        if (count >= cap) {
            cap *= 2;
            domains = realloc(domains, cap * sizeof(char *));
            hashes = realloc(hashes, cap * sizeof(uint32_t));
            ttls = realloc(ttls, cap * sizeof(uint32_t));
        }
        domains[count] = strdup(d);
        hashes[count] = hash_domain_name(d);
        ttls[count] = (n_parsed >= 2) ? file_ttl : ((ttl >= 5) ? (ttl - 2 + (hashes[count] % 5)) : ttl);
        count++;
    }
    fclose(f);

    /* 1. RRSET cache section */
    fprintf(pipe, "START_RRSET_CACHE\n");
    for (uint32_t i = 0; i < count; i++) {
        uint32_t h = hashes[i];
        uint8_t b1 = 10;
        uint8_t b2 = (uint8_t)((h >> 16) & 0xfe) | 1;
        uint8_t b3 = (uint8_t)((h >> 8) & 0xfe) | 1;
        uint8_t b4 = (uint8_t)(h & 0xfe) | 1;
        uint32_t entry_ttl = ttls[i];
        fprintf(pipe, ";rrset %u 1 0 5 0\n", entry_ttl);
        fprintf(pipe, "%s.\t%u\tIN\tA\t%u.%u.%u.%u\n", domains[i], entry_ttl, b1, b2, b3, b4);
    }
    fprintf(pipe, "END_RRSET_CACHE\n");

    /* 2. MSG cache section */
    fprintf(pipe, "START_MSG_CACHE\n");
    for (uint32_t i = 0; i < count; i++) {
        uint32_t entry_ttl = ttls[i];
        fprintf(pipe, "msg %s. IN A 33152 1 %u 0 1 0 0 -1\n", domains[i], entry_ttl);
        fprintf(pipe, "%s. IN A 0\n", domains[i]);
    }
    fprintf(pipe, "END_MSG_CACHE\n");
    fprintf(pipe, "EOF\n");

    int pclose_status = pclose(pipe);

    for (uint32_t i = 0; i < count; i++) {
        free(domains[i]);
    }
    free(domains);
    free(hashes);
    free(ttls);

    clock_gettime(CLOCK_MONOTONIC, &t_end);
    double elapsed_ms = (t_end.tv_sec - t_start.tv_sec) * 1000.0 + (t_end.tv_nsec - t_start.tv_nsec) / 1000000.0;

    if (pclose_status == 0) {
        printf("   ✓ [PRELOAD UNBOUND] Loaded %u domains into Unbound in %.1f ms (TTL=%us)\n",
               count, elapsed_ms, ttl);
        return 0;
    } else {
        fprintf(stderr, "   [WARN] unbound-control load_cache exited with status %d\n", pclose_status);
        return -1;
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <--hw|--driver|--unbound|--all> [trace_file] [ttl_seconds]\n", argv[0]);
        return 1;
    }

    const char *mode = argv[1];
    uint32_t ttl = (argc > 3) ? (uint32_t)atoi(argv[3]) : DEFAULT_TTL;

    if (strcmp(mode, "--hw") == 0) {
        const char *trace = (argc > 2) ? argv[2] : DEFAULT_HW_TRACE_FILE;
        return preload_hw(trace, ttl);
    } else if (strcmp(mode, "--driver") == 0) {
        const char *trace = (argc > 2) ? argv[2] : DEFAULT_HOST_TRACE_FILE;
        return preload_driver(trace, ttl);
    } else if (strcmp(mode, "--unbound") == 0) {
        const char *trace = (argc > 2) ? argv[2] : DEFAULT_HOST_TRACE_FILE;
        return preload_unbound(trace, ttl);
    } else if (strcmp(mode, "--all") == 0) {
        const char *host_trace = (argc > 2) ? argv[2] : DEFAULT_HOST_TRACE_FILE;
        const char *hw_trace = (argc > 2) ? argv[2] : DEFAULT_HW_TRACE_FILE;
        int r1 = preload_unbound(host_trace, ttl);
        int r2 = preload_driver(host_trace, ttl);
        int r3 = preload_hw(hw_trace, ttl);
        return (r1 || r2 || r3);
    } else {
        fprintf(stderr, "Unknown option: %s\n", mode);
        return 1;
    }
}
