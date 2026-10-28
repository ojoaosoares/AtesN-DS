#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <signal.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define BUFFER_SIZE 2048

static volatile int g_running = 1;
static uint64_t g_total_queries = 0;

static void sig_handler(int sig) {
    (void)sig;
    g_running = 0;
}

/* FNV-1a 32-bit hash function for domain names (case-insensitive) */
static uint32_t hash_domain(const uint8_t *buf, size_t len, size_t *qname_len) {
    uint32_t hash = 2166136261u;
    size_t off = 12; // DNS question begins at offset 12

    while (off < len && buf[off] != 0) {
        uint8_t labellen = buf[off++];
        if (off + labellen > len) break;
        for (uint8_t i = 0; i < labellen; i++) {
            uint8_t c = buf[off++];
            if (c >= 'A' && c <= 'Z') c += ('a' - 'A'); // normalize lowercase
            hash ^= c;
            hash *= 16777619u;
        }
        hash ^= '.';
        hash *= 16777619u;
    }

    if (off < len && buf[off] == 0) {
        off++; // consume terminating 0x00
    }

    *qname_len = off - 12;
    return hash;
}

struct domain_ttl_entry {
    uint32_t hash;
    uint32_t ttl;
};

static struct domain_ttl_entry *g_ttl_map = NULL;
static size_t g_ttl_map_size = 0;

static int cmp_ttl_entry(const void *a, const void *b) {
    const struct domain_ttl_entry *ea = (const struct domain_ttl_entry *)a;
    const struct domain_ttl_entry *eb = (const struct domain_ttl_entry *)b;
    if (ea->hash < eb->hash) return -1;
    if (ea->hash > eb->hash) return 1;
    return 0;
}

static uint32_t hash_domain_name_str(const char *domain) {
    uint32_t hash = 2166136261u;
    for (const char *p = domain; *p; p++) {
        uint8_t c = (uint8_t)*p;
        if (c >= 'A' && c <= 'Z') c += ('a' - 'A');
        hash ^= c;
        hash *= 16777619u;
    }
    hash ^= '.';
    hash *= 16777619u;
    return hash;
}

static void load_ttl_map(const char *filepath) {
    FILE *f = fopen(filepath, "r");
    if (!f) {
        printf("[MOCK DNS] Notice: No TTL map file at '%s' (using Option 1 percentiles fallback)\n", filepath);
        return;
    }
    size_t cap = 100000;
    g_ttl_map = (struct domain_ttl_entry *)malloc(cap * sizeof(struct domain_ttl_entry));
    if (!g_ttl_map) { fclose(f); return; }
    
    char line[512];
    size_t count = 0;
    while (fgets(line, sizeof(line), f)) {
        char dom[256];
        uint32_t ttl = 30;
        if (sscanf(line, "%255s %u", dom, &ttl) >= 1) {
            if (count >= cap) {
                cap *= 2;
                g_ttl_map = (struct domain_ttl_entry *)realloc(g_ttl_map, cap * sizeof(struct domain_ttl_entry));
            }
            g_ttl_map[count].hash = hash_domain_name_str(dom);
            g_ttl_map[count].ttl = ttl;
            count++;
        }
    }
    fclose(f);
    qsort(g_ttl_map, count, sizeof(struct domain_ttl_entry), cmp_ttl_entry);
    g_ttl_map_size = count;
    printf("✓ [MOCK DNS] Loaded %zu domain TTL mappings from %s\n", count, filepath);
}

/* Realistic empirical DNS TTL distribution (Option 1):
 * - 10% -> 10s
 * - 20% -> 30s
 * - 25% -> 60s
 * - 30% -> 300s (5 min)
 * - 10% -> 1800s (30 min)
 * - 5%  -> 86400s (24h)
 */
static uint32_t g_fixed_ttl = 0; // 0 = use Option 1 distribution

static uint32_t get_distributed_ttl(uint32_t hash) {
    if (g_fixed_ttl > 0) return g_fixed_ttl;
    if (g_ttl_map && g_ttl_map_size > 0) {
        struct domain_ttl_entry key = { .hash = hash };
        struct domain_ttl_entry *res = (struct domain_ttl_entry *)bsearch(
            &key, g_ttl_map, g_ttl_map_size, sizeof(struct domain_ttl_entry), cmp_ttl_entry);
        if (res) return res->ttl;
    }
    uint32_t p = hash % 100;
    if (p < 10) return 10;
    if (p < 30) return 30;
    if (p < 55) return 60;
    if (p < 85) return 300;
    if (p < 95) return 1800;
    return 86400;
}

/* Deterministic IPv4 generation: 10.x.y.z */
static uint32_t get_synthetic_ip(uint32_t hash) {
    uint8_t b1 = 10;
    uint8_t b2 = (uint8_t)((hash >> 16) & 0xfe) | 1; // avoid 0
    uint8_t b3 = (uint8_t)((hash >> 8) & 0xfe) | 1;
    uint8_t b4 = (uint8_t)(hash & 0xfe) | 1;
    return (b1 << 24) | (b2 << 16) | (b3 << 8) | b4;
}

int main(int argc, char *argv[]) {
    const char *listen_ip = (argc > 1) ? argv[1] : "192.168.0.2";
    int port = (argc > 2) ? atoi(argv[2]) : 53;
    if (argc > 3) {
        g_fixed_ttl = (uint32_t)atoi(argv[3]);
    }
    const char *ttl_file = (argc > 4) ? argv[4] : "tests/domain_ttl_map.txt";
    load_ttl_map(ttl_file);
    printf("[MOCK DNS] Serving on %s:%d (Fixed TTL: %u, 0=Option 1 Distribution)\n", listen_ip, port, g_fixed_ttl);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_REUSEPORT
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif

    // Increase UDP buffer sizes for high throughput
    int bufsize = 16 * 1024 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));

    struct sockaddr_in srv_addr;
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(port);
    inet_pton(AF_INET, listen_ip, &srv_addr.sin_addr);

    if (bind(sock, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) < 0) {
        perror("bind");
        fprintf(stderr, "Failed to bind to %s:%d\n", listen_ip, port);
        close(sock);
        return 1;
    }

    printf("===================================================================\n");
    printf("🚀 Mock Authoritative DNS Responder running on %s:%d\n", listen_ip, port);
    printf("   - Distributed TTLs: 10s (10%%), 60s (20%%), 300s (45%%), 1800s (15%%), 86400s (10%%)\n");
    printf("   - Synthetic IPs:    10.x.y.z (deterministic hash-based)\n");
    printf("===================================================================\n");
    fflush(stdout);

    uint8_t buf[BUFFER_SIZE];
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    time_t last_report = time(NULL);
    uint64_t last_queries = 0;

    while (g_running) {
        ssize_t n = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&client_addr, &client_len);
        if (n < 0) {
            if (!g_running) break;
            continue;
        }

        // Must at least contain DNS header (12 bytes) + 1 question (min 5 bytes)
        if (n < 17) continue;

        size_t qname_len = 0;
        uint32_t hash = hash_domain(buf, (size_t)n, &qname_len);

        size_t question_end = 12 + qname_len + 4; // qname + QTYPE (2) + QCLASS (2)
        if (question_end > (size_t)n) {
            continue; // Malformed packet
        }

        uint32_t ttl = get_distributed_ttl(hash);
        uint32_t ip = get_synthetic_ip(hash);

        // Build response header
        buf[2] = 0x81; // QR=1, Opcode=0, AA=1, TC=0, RD=1
        buf[3] = 0x80; // RA=1, Z=0, RCODE=0 (NOERROR)
        buf[4] = 0x00; buf[5] = 0x01; // QDCOUNT = 1
        buf[6] = 0x00; buf[7] = 0x01; // ANCOUNT = 1
        buf[8] = 0x00; buf[9] = 0x00; // NSCOUNT = 0
        buf[10] = 0x00; buf[11] = 0x00; // ARCOUNT = 0

        // Append 16-byte A Answer Record
        uint8_t *ans = buf + question_end;
        ans[0] = 0xc0; ans[1] = 0x0c; // Name: pointer to QNAME at offset 12
        ans[2] = 0x00; ans[3] = 0x01; // Type: A (1)
        ans[4] = 0x00; ans[5] = 0x01; // Class: IN (1)
        // TTL (4 bytes big-endian)
        ans[6] = (uint8_t)((ttl >> 24) & 0xff);
        ans[7] = (uint8_t)((ttl >> 16) & 0xff);
        ans[8] = (uint8_t)((ttl >> 8) & 0xff);
        ans[9] = (uint8_t)(ttl & 0xff);
        // RDLENGTH: 4 bytes
        ans[10] = 0x00; ans[11] = 0x04;
        // RDATA: IPv4
        ans[12] = (uint8_t)((ip >> 24) & 0xff);
        ans[13] = (uint8_t)((ip >> 16) & 0xff);
        ans[14] = (uint8_t)((ip >> 8) & 0xff);
        ans[15] = (uint8_t)(ip & 0xff);

        size_t resp_len = question_end + 16;
        sendto(sock, buf, resp_len, 0, (struct sockaddr *)&client_addr, client_len);
        g_total_queries++;

        time_t now = time(NULL);
        if (now - last_report >= 5) {
            uint64_t diff = g_total_queries - last_queries;
            printf("[MOCK-STATS] Total: %lu queries | Current QPS: %.1f\n",
                   g_total_queries, (double)diff / (now - last_report));
            fflush(stdout);
            last_report = now;
            last_queries = g_total_queries;
        }
    }

    printf("\n[MOCK-DNS] Stopped. Total queries answered: %lu\n", g_total_queries);
    close(sock);
    return 0;
}
