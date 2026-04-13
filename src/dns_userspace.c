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
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "dns.h"
#include "dns.skel.h"

#ifndef BPF_XDP
#define BPF_XDP 3
#endif

#define MAX_IP_STRING_LENGTH 16

static const char *standard_recursive_server = "8.8.8.8";

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

        printf("[EVENT] Received domain: %s\n", e->domain);        

        for (__u32 i = 0; i < e->len; i++) {
            struct in_addr dst = { .s_addr = e->ips[i] };
            printf(" -> %s\n", inet_ntoa(dst));

            int ret = send_dns_query_from_ip(
                myctx->saddr,
                e->port,
                e->ips[i],
                e->id,
                e->domain
            );

            if (ret == 0) {
                printf("[SEND] Sent to %s\n", inet_ntoa(dst));
            } else {
                fprintf(stderr, "[ERROR] Failed sending to %s\n", inet_ntoa(dst));
            }
        }
    }

    else if (len == sizeof(struct event_prefetch)) {

        struct event_prefetch *e = data;

        printf("[EVENT] Received domain: %s\n", e->domain);

        struct in_addr dst = { .s_addr = e->ip };
        printf(" -> %s\n", inet_ntoa(dst));

        int ret = send_dns_query_from_ip(
            myctx->saddr,
            e->port,
            e->ip,
            e->id,
            e->domain
        );

        if (ret == 0) {
            printf("[SEND] Sent pretech query to %s\n", inet_ntoa(dst));
        } else {
            fprintf(stderr, "[ERROR] Failed sending to %s\n", inet_ntoa(dst));
        }
    }

    return 0;
}



void tutorial() {
    printf("AtesN-DS\n");
    printf("Usage: sudo ./atesnds [options]\n");
    printf("  -h\tShow a help message\n");
    printf("  \t-i\t interface where attach the dns\n");
    printf("  \t-a\t ip address of your dev interface\n");
    printf("  \t-s\t the root dns server\n");
    printf("  \t-m\t mac of the gateway\n");
}

int main(int argc, char *argv[]) {
    fprintf(stderr, "Starting application...\n");
    struct dns *skel;
    skel = dns__open();

    if(!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    printf("BPF skeleton opened\n");

    if(dns__load(skel)) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        dns__destroy(skel);
        return 1;
    }
    
    printf("BPF skeleton loaded\n");

    if (!skel->bss) {
        fprintf(stderr, "Error: BPF skeleton has no BSS (global variables)\n");
        dns__destroy(skel);
        return 1;
    }

    int opt, index = 0;
    char recursive[MAX_IP_STRING_LENGTH], mac_address[18];
    memset(recursive, 0, sizeof(recursive));
    memset(mac_address, 0, sizeof(mac_address));

    strcpy(recursive, standard_recursive_server);

    __u32 myip = 0;
    optind = 1;

    while ((opt = getopt(argc, argv, "a:i:s:m:h")) != -1) {
        switch (opt) {
        case 'a':
            printf("Processing -a: %s\n", optarg);
            inet_pton(AF_INET, optarg, &myip);
            inet_pton(AF_INET, optarg, &skel->bss->serverip);
            break;
        case 'i':
            printf("Processing -i: %s\n", optarg);
            index = if_nametoindex(optarg);
            break;
        case 's':
            printf("Processing -s: %s\n", optarg);
            strncpy(recursive, optarg, sizeof(recursive)-1);
            break;
        case 'm':
            printf("Processing -m: %s\n", optarg);
            strncpy(mac_address, optarg, sizeof(mac_address)-1);
            break;
        case 'h':
        default:
            tutorial();
            dns__destroy(skel);
            return 1;
        }
    }

    if (index == 0)
    {
        printf("interface where the program will be attached is requeried \n");
        goto cleanup;
    }

    if(!validate_ipv4(recursive))
    {
        printf("Invalid recursive server\n");
        goto cleanup;
    }

    if (strlen(mac_address) == 0) {
        printf("MAC address is required\n");
        goto cleanup;
    }

    printf("Setting configuration...\n");
    convert_mac_to_bytes(mac_address, skel->bss->gateway_mac);
    inet_pton(AF_INET, recursive, &skel->bss->recursive_server_ip);

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
    
    printf("Updating tail call maps...\n");
    for (size_t i = 0; i < sizeof(programs) / sizeof(programs[0]); i++) {
        int fd = bpf_program__fd(programs[i].prog);
        if (fd < 0) {
            fprintf(stderr, "Failed to get FD for tail program index %zu\n", i);
            continue;
        }
        if (bpf_map_update_elem(bpf_map__fd(skel->maps.tail_programs), &programs[i].key, &fd, 0) < 0) {
            perror("bpf_map_update_elem");
        }
    }

    int fd = bpf_program__fd(skel->progs.dns_filter);
    printf("Attaching XDP program...\n");

    struct bpf_link_create_opts opts = {};
    opts.sz = sizeof(opts);
    
    int link_fd = bpf_link_create(fd, index, BPF_XDP, &opts);
    if (link_fd < 0) {
        perror("bpf_link_create failed, trying bpf_program__attach_xdp");
        if(bpf_program__attach_xdp(skel->progs.dns_filter, index) < 0) {
            fprintf(stderr, "Failed to attach XDP program\n");
            goto cleanup;
        }
    }

    printf("Program attached successfully\n");
    printf("CTRL + C to stop\n");

    struct send_packets_context sctx = {
        .saddr = myip
    };

    struct ring_buffer *rb;
    rb = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf_send_packet), handle_ringbuf_event, &sctx, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    while (1) {
        ring_buffer__poll(rb, 100);
    }
    
cleanup: 
    dns__destroy(skel);
    return 0;
}
