#ifndef DNS_PRELOAD_UTILS_H
#define DNS_PRELOAD_UTILS_H

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "dns.h"

/* djb2 hash function for deterministic domain name mapping */
static inline uint32_t hash_domain_name(const char *str) {
    uint32_t hash = 5381;
    int c;
    while ((c = (unsigned char)*str++)) {
        if (c >= 'A' && c <= 'Z') c += ('a' - 'A');
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

/* Deterministic IPv4 matching mock_dns_server.c: 10.b2.b3.b4 */
static inline uint32_t get_synthetic_ip(uint32_t hash) {
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
static inline int domain_to_wire(const char *name, uint8_t *wire, size_t max_len) {
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

#endif /* DNS_PRELOAD_UTILS_H */
