#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <errno.h>
#include <net/if.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "dns_listener.h"
#include "dns_listener.skel.h"

static volatile bool g_running = true;
static bool g_pinned_ringbuf = false;

static void sig_handler(int sig) {
    (void)sig;
    g_running = false;
}

static void print_usage(const char *prog) {
    printf("AtesN-DS Decoupled DNS Listener (TC Egress + XDP Ingress)\n");
    printf("Usage: sudo %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  -i, --interface <iface>   Target network interface (default: %s)\n", DEFAULT_LISTENER_IFACE);
    printf("  -r, --ringbuf <path>      Path to pinned hw_sync_ringbuf (default: %s)\n", DEFAULT_HW_SYNC_RINGBUF);
    printf("  -v, --verbose             Enable detailed telemetry logging\n");
    printf("  -h, --help                Show this help message\n");
}

int main(int argc, char *argv[]) {
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    struct listener_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.interface, DEFAULT_LISTENER_IFACE, sizeof(cfg.interface) - 1);
    strncpy(cfg.ringbuf_path, DEFAULT_HW_SYNC_RINGBUF, sizeof(cfg.ringbuf_path) - 1);
    cfg.verbose = false;

    static struct option long_options[] = {
        {"interface", required_argument, 0, 'i'},
        {"ringbuf",   required_argument, 0, 'r'},
        {"verbose",   no_argument,       0, 'v'},
        {"help",      no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    int xdp_link_fd = -1;
    while ((opt = getopt_long(argc, argv, "i:r:vh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'i':
                strncpy(cfg.interface, optarg, sizeof(cfg.interface) - 1);
                break;
            case 'r':
                strncpy(cfg.ringbuf_path, optarg, sizeof(cfg.ringbuf_path) - 1);
                break;
            case 'v':
                cfg.verbose = true;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    setrlimit(RLIMIT_MEMLOCK, &rlim);

    unsigned int ifindex = if_nametoindex(cfg.interface);
    if (!ifindex) {
        fprintf(stderr, "[ERROR] Interface '%s' not found: %s\n", cfg.interface, strerror(errno));
        return 1;
    }

    if (cfg.verbose) {
        printf("==========================================================\n");
        printf("🚀 AtesN-DS Decoupled DNS Listener\n");
        printf("   Interface:     %s (ifindex %u)\n", cfg.interface, ifindex);
        printf("   RingBuffer:    %s\n", cfg.ringbuf_path);
        printf("   TC Egress:     Tracking recursive queries\n");
        printf("   XDP Ingress:   Matching responses & submitting to SmartNIC\n");
        printf("==========================================================\n");
    }

    /* 1. Open BPF Skeleton */
    struct dns_listener *skel = dns_listener__open();
    if (!skel) {
        fprintf(stderr, "[ERROR] Failed to open DNS Listener skeleton.\n");
        return 1;
    }

    /* Reuse hw_sync_ringbuf if already pinned */
    int ringbuf_fd = bpf_obj_get(cfg.ringbuf_path);
    if (ringbuf_fd >= 0) {
        bpf_map__reuse_fd(skel->maps.hw_sync_ringbuf, ringbuf_fd);
        if (cfg.verbose)
            printf("[INFO] Reusing existing pinned hw_sync_ringbuf at %s\n", cfg.ringbuf_path);
    }

    /* 2. Load skeleton */
    int err = dns_listener__load(skel);
    if (err) {
        fprintf(stderr, "[ERROR] Failed to load DNS Listener skeleton (%d: %s)\n", err, strerror(-err));
        dns_listener__destroy(skel);
        if (ringbuf_fd >= 0) close(ringbuf_fd);
        return 1;
    }

    /* Pin hw_sync_ringbuf if not already pinned */
    if (ringbuf_fd < 0) {
        unlink(cfg.ringbuf_path);
        if (bpf_map__pin(skel->maps.hw_sync_ringbuf, cfg.ringbuf_path) == 0) {
            g_pinned_ringbuf = true;
            printf("[INFO] Pinned hw_sync_ringbuf to %s\n", cfg.ringbuf_path);
        } else {
            fprintf(stderr, "[WARN] Could not pin hw_sync_ringbuf to %s (%s)\n",
                    cfg.ringbuf_path, strerror(errno));
        }
    }

    /* 3. Attach TC Egress Hook */
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook,
        .ifindex = ifindex,
        .attach_point = BPF_TC_EGRESS
    );

    /* Create clsact qdisc if needed */
    bpf_tc_hook_create(&tc_hook);

    DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_clean_opts,
        .handle = 1,
        .priority = 1
    );
    bpf_tc_detach(&tc_hook, &tc_clean_opts);

    DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts,
        .handle = 1,
        .priority = 1,
        .flags = BPF_TC_F_REPLACE,
        .prog_fd = bpf_program__fd(skel->progs.tc_dns_egress)
    );

    err = bpf_tc_attach(&tc_hook, &tc_opts);
    if (err) {
        fprintf(stderr, "[ERROR] Failed to attach TC Egress filter (%d: %s)\n", err, strerror(-err));
        goto cleanup;
    }
    printf("✅ TC Egress filter attached to %s (fd %d)\n", cfg.interface, tc_opts.prog_fd);

    /* 4. Attach XDP Ingress Hook using bpf_link_create (coexists with xdpoffload) */
    int xdp_prog_fd = bpf_program__fd(skel->progs.xdp_dns_ingress);
    DECLARE_LIBBPF_OPTS(bpf_link_create_opts, link_opts);
    link_opts.sz = sizeof(link_opts);
    xdp_link_fd = bpf_link_create(xdp_prog_fd, ifindex, BPF_XDP, &link_opts);
    if (xdp_link_fd < 0) {
        if (cfg.verbose)
            printf("[INFO] bpf_link_create failed (%d), falling back to bpf_xdp_attach...\n", errno);
        int xdp_err = bpf_xdp_attach(ifindex, xdp_prog_fd, XDP_FLAGS_DRV_MODE, NULL);
        if (xdp_err < 0)
            xdp_err = bpf_xdp_attach(ifindex, xdp_prog_fd, XDP_FLAGS_SKB_MODE, NULL);
        if (xdp_err < 0) {
            fprintf(stderr, "[ERROR] Failed to attach XDP Ingress program: %s\n", strerror(errno));
            goto cleanup;
        }
    }
    printf("✅ XDP Ingress filter attached to %s (fd %d)\n", cfg.interface, xdp_prog_fd);

    printf("\n[DNS Listener] Running. Press CTRL+C to stop.\n");

    int stats_fd = bpf_map__fd(skel->maps.listener_stats_map);
    uint32_t zero = 0;
    struct listener_stats_val stats;

    while (g_running) {
        sleep(2);
        if (cfg.verbose && stats_fd >= 0) {
            if (bpf_map_lookup_elem(stats_fd, &zero, &stats) == 0) {
                printf("[DNS Listener] TC Egress Queries: %llu | XDP Ingress Matched: %llu | Sync Events: %llu\n",
                       (unsigned long long)stats.egress_queries_tracked,
                       (unsigned long long)stats.ingress_responses_matched,
                       (unsigned long long)stats.sync_events_submitted);
            }
        }
    }

    printf("\n[DNS Listener] Detaching filters and shutting down...\n");

cleanup:
    /* Detach XDP */
    if (xdp_link_fd >= 0) close(xdp_link_fd);
    bpf_xdp_detach(ifindex, XDP_FLAGS_DRV_MODE, NULL);
    bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);

    /* Detach TC */
    tc_opts.prog_fd = 0;
    tc_opts.prog_id = 0;
    bpf_tc_detach(&tc_hook, &tc_opts);

    /* Unpin if we pinned it */
    if (g_pinned_ringbuf) {
        bpf_map__unpin(skel->maps.hw_sync_ringbuf, cfg.ringbuf_path);
    }

    if (ringbuf_fd >= 0) close(ringbuf_fd);
    dns_listener__destroy(skel);

    printf("✅ DNS Listener terminated cleanly.\n");
    return 0;
}
