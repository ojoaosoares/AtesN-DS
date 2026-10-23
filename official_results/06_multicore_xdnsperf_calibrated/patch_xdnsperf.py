#!/usr/bin/env python3
import sys

path = '/home/soares/Documentos/xdnsperf/src/loadgen.c'
with open(path, 'r') as f:
    code = f.read()

# 1. Replace Latency Histogram definition
old_hist = """/* ------------------------------------------------------------------ */
/* High-Resolution Latency Histogram                                  */
/* ------------------------------------------------------------------ */
#define LAT_BUCKETS           200000      /* 0 to 200,000 µs (0.001 ms res)*/

typedef struct {
    uint64_t counts[LAT_BUCKETS];
    uint64_t total;
    uint64_t sum_us;
    uint64_t min_us;
    uint64_t max_us;
} LatencyHist;

static void lat_init(LatencyHist *h)
{
    memset(h, 0, sizeof(*h));
    h->min_us = UINT64_MAX;
}

static inline void lat_record(LatencyHist *h, uint64_t us)
{
    uint64_t bucket = (us < LAT_BUCKETS) ? us : (LAT_BUCKETS - 1);
    h->counts[bucket]++;
    h->total++;
    h->sum_us += us;
    if (us < h->min_us) h->min_us = us;
    if (us > h->max_us) h->max_us = us;
}

static double lat_percentile(const LatencyHist *h, double p)
{
    if (h->total == 0) return 0.0;
    uint64_t target = (uint64_t)(h->total * p / 100.0);
    uint64_t cum = 0;
    for (int i = 0; i < LAT_BUCKETS; i++) {
        cum += h->counts[i];
        if (cum >= target)
            return (double)i / 1000.0;
    }
    return (double)(LAT_BUCKETS - 1) / 1000.0;
}

static double lat_mean(const LatencyHist *h)
{
    if (h->total == 0) return 0.0;
    return (double)h->sum_us / h->total / 1000.0;
}

static double lat_stdev(const LatencyHist *h)
{
    if (h->total < 2) return 0.0;
    double mean_us = (double)h->sum_us / h->total;
    double var = 0.0;
    for (int i = 0; i < LAT_BUCKETS; i++) {
        if (!h->counts[i]) continue;
        double diff = (double)i - mean_us;
        var += h->counts[i] * diff * diff;
    }
    return sqrt(var / h->total) / 1000.0;
}"""

new_hist = """/* ------------------------------------------------------------------ */
/* High-Resolution Latency Histogram (0 to 5,000 ms, dnsperf equiv)   */
/* ------------------------------------------------------------------ */
#define LAT_TIER1_MAX_US      200000ULL       /* 0 to 200 ms at 1 us res */
#define LAT_TIER2_MAX_US      5000000ULL      /* 200 ms to 5000 ms at 100 us res */
#define LAT_TIER2_RES_US      100ULL          /* 100 us (0.1 ms) bucket width */
#define LAT_TIER2_BUCKETS     ((LAT_TIER2_MAX_US - LAT_TIER1_MAX_US) / LAT_TIER2_RES_US) /* 48,000 */
#define LAT_BUCKETS           (LAT_TIER1_MAX_US + LAT_TIER2_BUCKETS)                     /* 248,000 */

typedef struct {
    uint64_t counts[LAT_BUCKETS];
    uint64_t total;
    uint64_t sum_us;
    uint64_t min_us;
    uint64_t max_us;
} LatencyHist;

static void lat_init(LatencyHist *h)
{
    memset(h, 0, sizeof(*h));
    h->min_us = UINT64_MAX;
}

static inline uint32_t lat_to_bucket(uint64_t us)
{
    if (us < LAT_TIER1_MAX_US)
        return (uint32_t)us;
    if (us < LAT_TIER2_MAX_US)
        return (uint32_t)(LAT_TIER1_MAX_US + (us - LAT_TIER1_MAX_US) / LAT_TIER2_RES_US);
    return LAT_BUCKETS - 1;
}

static inline double bucket_to_ms(uint32_t bucket)
{
    if (bucket < LAT_TIER1_MAX_US)
        return (double)bucket / 1000.0;
    uint64_t us = LAT_TIER1_MAX_US + (uint64_t)(bucket - LAT_TIER1_MAX_US) * LAT_TIER2_RES_US;
    return (double)us / 1000.0;
}

static inline void lat_record(LatencyHist *h, uint64_t us)
{
    uint32_t bucket = lat_to_bucket(us);
    h->counts[bucket]++;
    h->total++;
    h->sum_us += us;
    if (us < h->min_us) h->min_us = us;
    if (us > h->max_us) h->max_us = us;
}

static double lat_percentile(const LatencyHist *h, double p)
{
    if (h->total == 0) return 0.0;
    uint64_t target = (uint64_t)(h->total * p / 100.0);
    uint64_t cum = 0;
    for (int i = 0; i < (int)LAT_BUCKETS; i++) {
        cum += h->counts[i];
        if (cum >= target)
            return bucket_to_ms((uint32_t)i);
    }
    return bucket_to_ms(LAT_BUCKETS - 1);
}

static double lat_mean(const LatencyHist *h)
{
    if (h->total == 0) return 0.0;
    return (double)h->sum_us / h->total / 1000.0;
}

static double lat_stdev(const LatencyHist *h)
{
    if (h->total < 2) return 0.0;
    double mean_us = (double)h->sum_us / h->total;
    double var = 0.0;
    for (int i = 0; i < (int)LAT_BUCKETS; i++) {
        if (!h->counts[i]) continue;
        double bucket_mid_us = (i < (int)LAT_TIER1_MAX_US)
            ? (double)i
            : (double)(LAT_TIER1_MAX_US + (uint64_t)(i - LAT_TIER1_MAX_US) * LAT_TIER2_RES_US + (LAT_TIER2_RES_US / 2));
        double diff = bucket_mid_us - mean_us;
        var += h->counts[i] * diff * diff;
    }
    return sqrt(var / h->total) / 1000.0;
}"""

if old_hist not in code:
    print("Error: old_hist not found in loadgen.c")
    sys.exit(1)

code = code.replace(old_hist, new_hist)

# 2. Update rx_worker timeout check to 5,000,000 us (5.0s)
code = code.replace('if (rtt_us < 2000000ULL) {', 'if (rtt_us < 5000000ULL) {')

# 3. Ensure snap is static in stats_worker and print_final_dnsperf_summary
code = code.replace('        LatencyHist snap;\n        lat_init(&snap);', '        static LatencyHist snap;\n        lat_init(&snap);')
code = code.replace('    LatencyHist snap;\n    lat_init(&snap);', '    static LatencyHist snap;\n    lat_init(&snap);')

# 4. Fix cur_frame ordering in tx_worker
old_tx_loop = """            uint64_t f_addr = cur_frame * FRAME_SIZE;
            cur_frame++;
            if (cur_frame >= frame_start + frame_count)
                cur_frame = frame_start;

            uint8_t *pkt = (uint8_t *)umem + f_addr;"""

new_tx_loop = """            uint64_t f_addr = cur_frame * FRAME_SIZE;
            int cur_ts_off = w->ts_offsets[cur_frame];
            int cur_pkt_len = w->frame_lens[cur_frame];
            cur_frame++;
            if (cur_frame >= frame_start + frame_count)
                cur_frame = frame_start;

            uint8_t *pkt = (uint8_t *)umem + f_addr;"""

if old_tx_loop in code:
    code = code.replace(old_tx_loop, new_tx_loop)

old_dupl = """            /* Record send timestamp indexed by host TxID */
            w->tx_timestamps[txid_host] = send_ns;
            int cur_ts_off = w->ts_offsets[cur_frame];
            int cur_pkt_len = w->frame_lens[cur_frame];
            memcpy(pkt + cur_ts_off, &send_ns, 8);"""

new_dupl = """            /* Record send timestamp indexed by host TxID */
            w->tx_timestamps[txid_host] = send_ns;
            memcpy(pkt + cur_ts_off, &send_ns, 8);"""

if old_dupl in code:
    code = code.replace(old_dupl, new_dupl)

with open(path, 'w') as f:
    f.write(code)

print("Patch applied successfully to loadgen.c!")
