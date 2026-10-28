#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "daemon_prefetch.h"

int build_dns_query(char *buf, size_t buf_size, uint16_t id, const char *domain) {
    if (buf_size < 12 + strlen(domain) + 2 + 4) return -1;
    memset(buf, 0, buf_size);
    buf[0] = (id >> 8) & 0xFF;
    buf[1] = id & 0xFF;
    buf[2] = 0x01; /* RD=1 */
    buf[4] = 0x00; buf[5] = 0x01; /* QDCOUNT = 1 */

    size_t offset = 12;
    int i = 0;
    while (i < 255 && domain[i]) {
        buf[offset++] = domain[i++];
    }
    if (offset + 1 + 4 > buf_size) return -1;
    buf[offset++] = 0x00;
    buf[offset++] = 0x00; buf[offset++] = 0x01; /* QTYPE A */
    buf[offset++] = 0x00; buf[offset++] = 0x01; /* QCLASS IN */
    return (int)offset;
}

int send_dns_query_from_ip(__u32 src_ip, __u16 src_port,
                           __u32 dst_ip, uint16_t id,
                           const char *domain) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    struct sockaddr_in src_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(src_port),
        .sin_addr.s_addr = src_ip
    };

    if (bind(sock, (struct sockaddr*)&src_addr, sizeof(src_addr)) < 0) {
        close(sock);
        return -1;
    }

    char query[512];
    int query_len = build_dns_query(query, sizeof(query), id, domain);
    if (query_len < 0) {
        close(sock);
        return -1;
    }

    struct sockaddr_in dst_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(53),
        .sin_addr.s_addr = dst_ip
    };

    ssize_t sent = sendto(sock, query, query_len, 0, (struct sockaddr*)&dst_addr, sizeof(dst_addr));
    close(sock);
    return sent > 0 ? 0 : -1;
}

int handle_resolver_sample(void *ctx, void *data, size_t len) {
    struct daemon_ctx *d = (struct daemon_ctx *)ctx;
    if (len == sizeof(struct event_prefetch)) {
        const struct event_prefetch *e = (const struct event_prefetch *)data;
        send_dns_query_from_ip(d->cfg.resolver_src_ip, e->port, e->ip, e->id, e->domain);
    } else if (len == sizeof(struct event_error_p)) {
        const struct event_error_p *e = (const struct event_error_p *)data;
        for (__u32 i = 0; i < e->len && i < 4; i++) {
            send_dns_query_from_ip(d->cfg.resolver_src_ip, e->port, e->ips[i], e->id, e->domain);
        }
    }
    return 0;
}

void *resolver_worker_thread(void *arg) {
    struct daemon_ctx *d = (struct daemon_ctx *)arg;
    pin_to_core(d->cfg.resolver_core);

    if (d->cfg.verbose)
        printf("[Resolver Worker] Thread started on core %d (Prefetch & Error Recovery)\n", d->cfg.resolver_core);

    while (d->running) {
        int err = ring_buffer__poll(d->rb_resolver, 20 /* timeout_ms */);
        if (err < 0 && err != -EINTR) break;
    }

    if (d->cfg.verbose)
        printf("[Resolver Worker] Exiting...\n");
    return NULL;
}
