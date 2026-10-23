#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/stat.h>
#include <regex.h>
#include <getopt.h>
#include <netinet/ip.h>
#include <linux/if_link.h>
#include <sys/resource.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "dns.h"
#include "dns.skel.h"

#ifndef BPF_XDP
#define BPF_XDP 3
#endif

#define MAX_IP_STRING_LENGTH 16

static const char *standard_recursive_server = "8.8.8.8";
static bool g_verbose = false;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    if (level == LIBBPF_DEBUG && !g_verbose)
        return 0;
    return vfprintf(stderr, format, args);
}

struct send_packets_context {
    __u32 saddr;
};


void convert_mac_to_bytes(const char *mac_str, unsigned char mac_bytes[6]) {

    char hex[3];
    hex[2] = '\0';
    char *end;

    for( uint8_t i = 0; i < 6; i++ )
    {
        hex[0] = mac_str[2*i + i];
        hex[1] = mac_str[2*i + i + 1];
        mac_bytes[i] = strtol(hex, &end, 16);
    }
}

int validate_ipv4(const char *ip_str) {
    regex_t regex;
    int reti;
    
    char *ipv4_pattern = "^([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})$";
    
    reti = regcomp(&regex, ipv4_pattern, REG_EXTENDED);
    if (reti) {
        printf("Error: it wasn't possible to compile regex\n");
        return 0;
    }

    reti = regexec(&regex, ip_str, 0, NULL, 0);
    if (!reti) {
        regfree(&regex);
        return 1;
    }
    
    else if (reti == REG_NOMATCH) {
        printf("%s isn't a valid IPv4 address\n", ip_str);
    }

    else 
        printf("Error: regex error\n");
    

    regfree(&regex);
    return 0;
}

static int build_dns_query(char *buf, size_t buf_size, uint16_t id, const char *domain) {
    if (buf_size < 12 + strlen(domain) + 2 + 4) {
        // Minimum DNS header + domain labels + null + QTYPE/QCLASS
        return -1;
    }

    memset(buf, 0, buf_size);

    // --- DNS Header (12 bytes) ---
    buf[0] = (id >> 8) & 0xFF;
    buf[1] = id & 0xFF;
    buf[2] = 0x01;  // QR=0 (query), Opcode=0, RD=1
    buf[3] = 0x00;
    buf[4] = 0x00; buf[5] = 0x01; // QDCOUNT = 1
    buf[6] = 0x00; buf[7] = 0x00; // ANCOUNT = 0
    buf[8] = 0x00; buf[9] = 0x00; // NSCOUNT = 0
    buf[10] = 0x00; buf[11] = 0x00; // ARCOUNT = 0

    size_t offset = 12;

    // --- Encode domain name ---
    int i = 0;
    while (i < 255 && domain[i]) {
        buf[offset++] = domain[i++];
    }

    if (offset + 1 + 4 > buf_size) return -1;
    buf[offset++] = 0x00;  // End of QNAME

    // --- QTYPE (A record) ---
    buf[offset++] = 0x00;
    buf[offset++] = 0x01;

    // --- QCLASS (IN) ---
    buf[offset++] = 0x00;
    buf[offset++] = 0x01;

    return (int)offset;
}

static int send_dns_query_from_ip(__u32 src_ip, __u16 src_port,
                                  __u32 dst_ip, uint16_t id,
                                  const char *domain) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_in src_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(src_port),
        .sin_addr.s_addr = src_ip
    };

    if (bind(sock, (struct sockaddr*)&src_addr, sizeof(src_addr)) < 0) {
        perror("bind");
        close(sock);
        return -1;
    }

    char query[271];
    int query_len = build_dns_query(query, sizeof(query), id, domain);
    if (query_len < 0) {
        fprintf(stderr, "failed to build query\n");
        close(sock);
        return -1;
    }

    
    struct sockaddr_in dst_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(53),
        .sin_addr.s_addr = dst_ip
    };

    
    if (sendto(sock, query, query_len, 0,
               (struct sockaddr*)&dst_addr, sizeof(dst_addr)) < 0) {
        perror("sendto");
        close(sock);
        return -1;
    }

    close(sock);
    return 0;
}

static int handle_ringbuf_event(void *ctx, void *data, size_t len) {
    struct send_packets_context *myctx = ctx;

    if (len == sizeof(struct event_error_p))
    {
        struct event_error_p *e = data;

        if (g_verbose)
            printf("[EVENT] Received domain: %s\n", e->domain);        

        for (__u32 i = 0; i < e->len; i++) {
            struct in_addr dst = { .s_addr = e->ips[i] };
            if (g_verbose)
                printf(" -> %s\n", inet_ntoa(dst));

            int ret = send_dns_query_from_ip(
                myctx->saddr,
                e->port,
                e->ips[i],
                e->id,
                e->domain
            );

            if (g_verbose) {
                if (ret == 0) {
                    printf("[SEND] Sent to %s\n", inet_ntoa(dst));
                } else {
                    fprintf(stderr, "[ERROR] Failed sending to %s\n", inet_ntoa(dst));
                }
            }
        }
    }

    else if (len == sizeof(struct event_prefetch)) {

        struct event_prefetch *e = data;

        if (g_verbose) {
            printf("[EVENT] Received domain: %s\n", e->domain);
            struct in_addr dst = { .s_addr = e->ip };
            printf(" -> %s\n", inet_ntoa(dst));
        }

        int ret = send_dns_query_from_ip(
            myctx->saddr,
            e->port,
            e->ip,
            e->id,
            e->domain
        );

        if (g_verbose) {
            struct in_addr dst = { .s_addr = e->ip };
            if (ret == 0) {
                printf("[SEND] Sent pretech query to %s\n", inet_ntoa(dst));
            } else {
                fprintf(stderr, "[ERROR] Failed sending to %s\n", inet_ntoa(dst));
            }
        }
    }

    return 0;
}

void tutorial() {
    printf("AtesN-DS Proxy Server\n");
    printf("Usage: sudo ./atesnds [options]\n");
    printf("  -h, --help                     Show this help message\n");
    printf("  -i <iface>                     Interface to attach XDP (required)\n");
    printf("  -a <ip>                        IPv4 address of your interface\n");
    printf("  -s <ip>                        Upstream recursive DNS server (default: 8.8.8.8)\n");
    printf("  -m <mac>                       MAC address of the gateway\n");
    printf("  -C, --cache-size <entries>     Max entries for cache_arecords (default: 4000000)\n");
    printf("  -N, --ns-cache-size <entries>  Max entries for cache_nsrecords (default: 8000000)\n");
    printf("  -Q, --queries-size <entries>   Max entries for new_queries (default: 4587576)\n");
    printf("  -v, --verbose                  Enable verbose packet and lifecycle logs\n");
    printf("  -q, --quiet                    Disable all non-error output (default)\n");
}

int main(int argc, char *argv[]) {
    setlinebuf(stdout);
    setlinebuf(stderr);
    libbpf_set_print(libbpf_print_fn);

    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &rlim) < 0) {
        perror("setrlimit(RLIMIT_MEMLOCK)");
    }

    int opt, index = 0;
    char recursive[MAX_IP_STRING_LENGTH], mac_address[18];
    memset(recursive, 0, sizeof(recursive));
    memset(mac_address, 0, sizeof(mac_address));
    strcpy(recursive, standard_recursive_server);

    __u32 myip = 0;
    uint32_t sw_cache_size = 0;
    uint32_t ns_cache_size = 0;
    uint32_t queries_size = 0;

    static struct option long_options[] = {
        {"help",          no_argument,       0, 'h'},
        {"cache-size",    required_argument, 0, 'C'},
        {"ns-cache-size", required_argument, 0, 'N'},
        {"queries-size",  required_argument, 0, 'Q'},
        {"verbose",       no_argument,       0, 'v'},
        {"quiet",         no_argument,       0, 'q'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "a:i:s:m:C:N:Q:vqh", long_options, NULL)) != -1) {
        switch (opt) {
        case 'a':
            inet_pton(AF_INET, optarg, &myip);
            break;
        case 'i':
            index = if_nametoindex(optarg);
            break;
        case 's':
            strncpy(recursive, optarg, sizeof(recursive)-1);
            break;
        case 'm':
            strncpy(mac_address, optarg, sizeof(mac_address)-1);
            break;
        case 'C':
            sw_cache_size = (uint32_t)strtoul(optarg, NULL, 10);
            break;
        case 'N':
            ns_cache_size = (uint32_t)strtoul(optarg, NULL, 10);
            break;
        case 'Q':
            queries_size = (uint32_t)strtoul(optarg, NULL, 10);
            break;
        case 'v':
            g_verbose = true;
            break;
        case 'q':
            g_verbose = false;
            break;
        case 'h':
        default:
            tutorial();
            return (opt == 'h') ? 0 : 1;
        }
    }

    if (index == 0) {
        fprintf(stderr, "[ERROR] Interface where program will be attached is required (-i <iface>)\n");
        return 1;
    }

    if (!validate_ipv4(recursive)) {
        fprintf(stderr, "[ERROR] Invalid recursive server IP: %s\n", recursive);
        return 1;
    }

    if (strlen(mac_address) == 0) {
        fprintf(stderr, "[ERROR] Gateway MAC address is required (-m <mac>)\n");
        return 1;
    }

    printf("[ATES-INIT] Step 1/6: Opening BPF skeleton...\n");
    fflush(stdout);
    struct dns *skel = dns__open();
    if (!skel) {
        fprintf(stderr, "[ERROR] Failed to open BPF skeleton (errno %d: %s)\n", errno, strerror(errno));
        fflush(stderr);
        return 1;
    }
    printf("[ATES-INIT] BPF skeleton opened successfully (%p)\n", (void*)skel);
    fflush(stdout);

    if (sw_cache_size > 0) {
        printf("[CONFIG] Resizing cache_arecords to %u entries...\n", sw_cache_size);
        fflush(stdout);
        bpf_map__set_max_entries(skel->maps.cache_arecords, sw_cache_size);
    }
    if (ns_cache_size > 0) {
        printf("[CONFIG] Resizing cache_nsrecords to %u entries...\n", ns_cache_size);
        fflush(stdout);
        bpf_map__set_max_entries(skel->maps.cache_nsrecords, ns_cache_size);
    }
    if (queries_size > 0) {
        printf("[CONFIG] Resizing new_queries to %u entries...\n", queries_size);
        fflush(stdout);
        bpf_map__set_max_entries(skel->maps.new_queries, queries_size);
    }

    printf("[ATES-INIT] Step 2/6: Loading BPF skeleton into kernel (allocating maps & verifying progs)...\n");
    fflush(stdout);
    int load_err = dns__load(skel);
    if (load_err) {
        fprintf(stderr, "[ERROR] Failed to load BPF skeleton into kernel (err %d, errno %d: %s)\n",
                load_err, errno, strerror(errno));
        fflush(stderr);
        dns__destroy(skel);
        return 1;
    }
    printf("[ATES-INIT] BPF skeleton loaded successfully into kernel!\n");
    fflush(stdout);

    printf("[ATES-INIT] Step 3/6: Checking BSS global variables...\n");
    fflush(stdout);
    if (!skel->bss) {
        fprintf(stderr, "[ERROR] BPF skeleton has no BSS (global variables)\n");
        fflush(stderr);
        dns__destroy(skel);
        return 1;
    }

    printf("[ATES-INIT] Step 4/6: Configuring network globals (Server IP, MAC, Upstream)...\n");
    fflush(stdout);
    skel->bss->serverip = myip;
    convert_mac_to_bytes(mac_address, skel->bss->gateway_mac);
    inet_pton(AF_INET, recursive, &skel->bss->recursive_server_ip);

    printf("[ATES-INIT] Step 5/6: Populating tail call programs map...\n");
    struct {
        int key;
        struct bpf_program *prog;
    } programs[] = {
        {DNS_JUMP_QUERY_PROG, skel->progs.dns_jump_query},
        {DNS_CREATE_NEW_QUERY_PROG, skel->progs.dns_create_new_query},
        {DNS_BACK_TO_LAST_QUERY, skel->progs.dns_back_to_last_query},
        {DNS_CHECK_SUBDOMAIN_PROG, skel->progs.dns_check_subdomain},
        {DNS_ERROR_PROG, skel->progs.dns_error},
        {DNS_ERROR_PREVENTION_PROG, skel->progs.dns_error_prevention},
        {DNS_RESPONSE_PROG, skel->progs.dns_response},
        {DNS_PRE_FETCH_PROG, skel->progs.dns_pre_fetch}
    };
    
    for (size_t i = 0; i < sizeof(programs) / sizeof(programs[0]); i++) {
        int prog_fd = bpf_program__fd(programs[i].prog);
        if (prog_fd < 0) {
            fprintf(stderr, "[ERROR] Failed to get FD for tail program index %zu\n", i);
            continue;
        }
        if (bpf_map_update_elem(bpf_map__fd(skel->maps.tail_programs), &programs[i].key, &prog_fd, 0) < 0) {
            perror("bpf_map_update_elem");
        }
    }

    printf("[ATES-INIT] Step 6/6: Attaching XDP program to interface %d...\n", index);
    int fd = bpf_program__fd(skel->progs.dns_filter);
    int exit_code = 0;
    struct bpf_link_create_opts opts = {};
    opts.sz = sizeof(opts);
    
    int link_fd = bpf_link_create(fd, index, BPF_XDP, &opts);
    if (link_fd < 0) {
        if (g_verbose) {
            fprintf(stderr, "[DEBUG] bpf_link_create failed (errno %d: %s), trying bpf_program__attach_xdp...\n", errno, strerror(errno));
        }
        struct bpf_link *link = bpf_program__attach_xdp(skel->progs.dns_filter, index);
        long link_err = libbpf_get_error(link);
        if (!link || link_err) {
            if (g_verbose) {
                fprintf(stderr, "[DEBUG] bpf_program__attach_xdp failed (err %ld), trying bpf_xdp_attach...\n", link_err);
            }
            int attach_err = bpf_xdp_attach(index, fd, XDP_FLAGS_DRV_MODE, NULL);
            if (attach_err < 0) {
                attach_err = bpf_xdp_attach(index, fd, XDP_FLAGS_SKB_MODE, NULL);
            }
            if (attach_err < 0) {
                attach_err = bpf_xdp_attach(index, fd, 0, NULL);
            }
            if (attach_err < 0) {
                fprintf(stderr, "[ERROR] Failed to attach XDP program to interface %d (errno %d: %s)\n",
                        index, errno, strerror(errno));
                exit_code = 1;
                goto cleanup;
            }
        }
    }

    if (g_verbose) {
        printf("Program attached successfully\n");
        printf("CTRL + C to stop\n");
    }

    struct bpf_map *hw_sync_map = bpf_object__find_map_by_name(skel->obj, "hw_sync_ringbuf");
    if (hw_sync_map) {
        unlink("/sys/fs/bpf/hw_sync_ringbuf");
        bpf_map__pin(hw_sync_map, "/sys/fs/bpf/hw_sync_ringbuf");
    }

    struct bpf_map *ovl_map = bpf_object__find_map_by_name(skel->obj, "overload_ctrl");
    if (ovl_map && !bpf_map__is_pinned(ovl_map)) {
        bpf_map__pin(ovl_map, "/sys/fs/bpf/overload_ctrl");
    }

    struct send_packets_context sctx = {
        .saddr = myip
    };

    struct ring_buffer *rb;
    rb = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf_send_packet), handle_ringbuf_event, &sctx, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        exit_code = 1;
        goto cleanup;
    }

    while (1) {
        ring_buffer__poll(rb, 100);
    }
    
cleanup: 
    if (hw_sync_map) {
        bpf_map__unpin(hw_sync_map, "/sys/fs/bpf/hw_sync_ringbuf");
    }
    if (ovl_map) {
        bpf_map__unpin(ovl_map, "/sys/fs/bpf/overload_ctrl");
    }
    dns__destroy(skel);
    return exit_code;
}

