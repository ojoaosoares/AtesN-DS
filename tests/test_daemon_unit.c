/**
 * @file test_daemon_unit.c
 * @brief Unit tests for AtesN-DS Control-Plane Daemon and Timing Wheel
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <time.h>

#include "dns.h"
#include "daemon_timing_wheel.h"
#include "daemon_context.h"
#include "daemon_ingest.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST_ASSERT(cond, msg) do { \
    tests_run++; \
    if (!(cond)) { \
        printf("  ❌ FAIL: %s (line %d)\n", msg, __LINE__); \
        return false; \
    } else { \
        tests_passed++; \
    } \
} while (0)

/* ------------------------------------------------------------------------- */
/* 1. Test Timing Wheel Initialization and Destruction                       */
/* ------------------------------------------------------------------------- */
static bool test_timing_wheel_create_destroy(void) {
    printf("[TEST] Timing Wheel: Create and Destroy\n");

    struct timing_wheel *w = timing_wheel_create(WHEEL_SECONDS_CAPACITY);
    TEST_ASSERT(w != NULL, "timing_wheel_create returned NULL");
    TEST_ASSERT(w->capacity == WHEEL_SECONDS_CAPACITY, "capacity mismatch");
    TEST_ASSERT(w->total_entries == 0, "initial total_entries must be 0");
    TEST_ASSERT(w->buckets != NULL, "buckets array must be allocated");

    timing_wheel_destroy(w);
    return true;
}

/* ------------------------------------------------------------------------- */
/* 2. Test Single & Multiple Key Insertions with Hash Collisions             */
/* ------------------------------------------------------------------------- */
static bool test_timing_wheel_insert(void) {
    printf("[TEST] Timing Wheel: Insertions & Bucket Collision Handling\n");

    struct timing_wheel *w = timing_wheel_create(100);
    TEST_ASSERT(w != NULL, "wheel creation failed");

    uint32_t now = 1000;

    /* Insert 3 keys at distinct timestamps */
    int ret1 = timing_wheel_insert(w, "domain-a.com", now + 10);
    int ret2 = timing_wheel_insert(w, "domain-b.com", now + 20);
    int ret3 = timing_wheel_insert(w, "domain-c.com", now + 30);

    TEST_ASSERT(ret1 == 0 && ret2 == 0 && ret3 == 0, "insert return codes must be 0");
    TEST_ASSERT(w->total_entries == 3, "total_entries must be 3");

    /* Insert 2 keys at the EXACT same timestamp (collision in bucket) */
    int ret4 = timing_wheel_insert(w, "collision-1.com", now + 50);
    int ret5 = timing_wheel_insert(w, "collision-2.com", now + 50);

    TEST_ASSERT(ret4 == 0 && ret5 == 0, "collision insert failed");
    TEST_ASSERT(w->total_entries == 5, "total_entries must be 5");

    uint32_t col_bucket = (now + 50) % w->capacity;
    TEST_ASSERT(w->buckets[col_bucket] != NULL, "bucket must not be empty");
    TEST_ASSERT(w->buckets[col_bucket]->next != NULL, "bucket must have collision list");

    timing_wheel_destroy(w);
    return true;
}

/* ------------------------------------------------------------------------- */
/* 3. Test Zero-PCIe-Read Expiration Sweeping                                */
/* ------------------------------------------------------------------------- */
static bool test_timing_wheel_pop_expired(void) {
    printf("[TEST] Timing Wheel: Zero-PCIe-Read Expiration Sweeping\n");

    struct timing_wheel *w = timing_wheel_create(1000);
    TEST_ASSERT(w != NULL, "wheel creation failed");

    uint32_t start_time = 5000;
    w->last_tick = start_time;

    /* Add entries expiring at: 5010, 5020, 5030, 5080 */
    timing_wheel_insert(w, "expired-first.com", 5010);
    timing_wheel_insert(w, "expired-second.com", 5020);
    timing_wheel_insert(w, "expired-third.com", 5030);
    timing_wheel_insert(w, "future-record.com", 5080);
    TEST_ASSERT(w->total_entries == 4, "total entries must be 4");

    /* Tick at T=5005 (nothing should expire yet) */
    uint32_t count = 0;
    struct wheel_node *exp = timing_wheel_pop_expired(w, 5005, &count);
    TEST_ASSERT(exp == NULL, "no keys should expire at T=5005");
    TEST_ASSERT(count == 0, "count must be 0");
    TEST_ASSERT(w->total_entries == 4, "total_entries must stay 4");

    /* Tick at T=5025 (5010 and 5020 must expire, 5030 and 5080 must stay) */
    exp = timing_wheel_pop_expired(w, 5025, &count);
    TEST_ASSERT(count == 2, "exactly 2 keys must expire");
    TEST_ASSERT(w->total_entries == 2, "2 keys must remain in wheel");

    /* Validate and free popped nodes */
    int popped_seen = 0;
    while (exp) {
        struct wheel_node *next = exp->next;
        popped_seen++;
        free(exp);
        exp = next;
    }
    TEST_ASSERT(popped_seen == 2, "popped linked list length must be 2");

    /* Tick at T=5100 (remaining 5030 and 5080 must expire) */
    exp = timing_wheel_pop_expired(w, 5100, &count);
    TEST_ASSERT(count == 2, "remaining 2 keys must expire");
    TEST_ASSERT(w->total_entries == 0, "wheel must now be empty");

    while (exp) {
        struct wheel_node *next = exp->next;
        free(exp);
        exp = next;
    }

    timing_wheel_destroy(w);
    return true;
}

/* ------------------------------------------------------------------------- */
/* 4. Test Proactive Watermark-Driven Min-TTL Eviction                        */
/* ------------------------------------------------------------------------- */
static bool test_timing_wheel_pop_min_ttl(void) {
    printf("[TEST] Timing Wheel: Proactive Min-TTL Eviction\n");

    struct timing_wheel *w = timing_wheel_create(1000);
    TEST_ASSERT(w != NULL, "wheel creation failed");

    uint32_t now = 10000;
    w->last_tick = now;

    /* Insert records with ascending TTLs */
    timing_wheel_insert(w, "ttl-10.com", now + 10);
    timing_wheel_insert(w, "ttl-20.com", now + 20);
    timing_wheel_insert(w, "ttl-30.com", now + 30);
    timing_wheel_insert(w, "ttl-40.com", now + 40);
    timing_wheel_insert(w, "ttl-50.com", now + 50);

    TEST_ASSERT(w->total_entries == 5, "total_entries must be 5");

    /* Request proactive eviction of the 2 keys with lowest remaining TTL */
    uint32_t evicted_count = 0;
    struct wheel_node *lru = timing_wheel_pop_min_ttl(w, now, 2, &evicted_count);

    TEST_ASSERT(evicted_count == 2, "evicted count must be 2");
    TEST_ASSERT(w->total_entries == 3, "remaining entries must be 3");

    /* Verify the evicted keys were indeed the lowest TTLs (ttl-10 and ttl-20) */
    bool saw_10 = false, saw_20 = false;
    while (lru) {
        struct wheel_node *next = lru->next;
        if (strcmp(lru->name, "ttl-10.com") == 0) saw_10 = true;
        if (strcmp(lru->name, "ttl-20.com") == 0) saw_20 = true;
        free(lru);
        lru = next;
    }
    TEST_ASSERT(saw_10 && saw_20, "Min-TTL must evict the lowest TTLs first");

    timing_wheel_destroy(w);
    return true;
}

/* ------------------------------------------------------------------------- */
/* 5. Test Hardware Key Boundary and Zero-Padding Integrity                  */
/* ------------------------------------------------------------------------- */
static bool test_hw_key_boundary(void) {
    printf("[TEST] Hardware %dB Key Boundary & Zero-Padding\n", MAX_DNS_NAME_LENGTH_HW);

    struct timing_wheel *w = timing_wheel_create(1000);
    TEST_ASSERT(w != NULL, "wheel creation failed");
    w->last_tick = 19000;

    /* Create exact MAX_DNS_NAME_LENGTH_HW key */
    char full_hw_key[MAX_DNS_NAME_LENGTH_HW];
    for (int i = 0; i < MAX_DNS_NAME_LENGTH_HW - 1; i++) {
        full_hw_key[i] = 'a' + (i % 26);
    }
    full_hw_key[MAX_DNS_NAME_LENGTH_HW - 1] = '\0';

    int ret = timing_wheel_insert(w, full_hw_key, 20000);
    TEST_ASSERT(ret == 0, "insert hw key failed");

    uint32_t count = 0;
    struct wheel_node *node = timing_wheel_pop_expired(w, 25000, &count);
    TEST_ASSERT(count == 1, "popped count must be 1");
    TEST_ASSERT(node != NULL, "node must not be null");
    TEST_ASSERT(memcmp(node->name, full_hw_key, MAX_DNS_NAME_LENGTH_HW) == 0,
                "hardware key data must be preserved byte-for-byte");

    free(node);
    timing_wheel_destroy(w);
    return true;
}

/* ------------------------------------------------------------------------- */
/* 6. Test Ingestion Sample Event Handler                                    */
/* ------------------------------------------------------------------------- */
static bool test_ingest_event_handler(void) {
    printf("[TEST] Daemon Ingest: Sample Event Handler\n");

    struct daemon_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.wheel = timing_wheel_create(1000);
    ctx.cfg.hw_cache_capacity = DEFAULT_HW_CACHE_CAPACITY;
    uint32_t now = (uint32_t)time(NULL);
    ctx.wheel->last_tick = now - 5;
    ctx.hw_cache_fd = -1; /* Simulated without hardware map */

    struct hw_cache_sync_event evt;
    memset(&evt, 0, sizeof(evt));
    strncpy(evt.name, "ingest-test.org", sizeof(evt.name) - 1);
    evt.ip = 0x0100007f; /* 127.0.0.1 */
    evt.timestamp = now + 10;

    int ret = handle_hw_sync_sample(&ctx, &evt, sizeof(evt));
    TEST_ASSERT(ret == 0, "sample handler return code must be 0");
    TEST_ASSERT(ctx.wheel->total_entries == 1, "event must be registered in timing wheel");

    /* Duplicate sample for the SAME domain with refreshed TTL: must NOT increase entries or evict */
    evt.timestamp = now + 20;
    ret = handle_hw_sync_sample(&ctx, &evt, sizeof(evt));
    TEST_ASSERT(ret == 0, "duplicate sample handler return code must be 0");
    TEST_ASSERT(ctx.wheel->total_entries == 1, "duplicate sample must NOT increment total_entries");

    uint32_t count = 0;
    /* At now + 15: old TTL was 10, but renewed to 20, so nothing must expire */
    struct wheel_node *node_early = timing_wheel_pop_expired(ctx.wheel, now + 15, &count);
    TEST_ASSERT(count == 0, "renewed domain must NOT expire at old timestamp");
    TEST_ASSERT(node_early == NULL, "popped node must be NULL");
    TEST_ASSERT(ctx.wheel->total_entries == 1, "total_entries must remain 1");

    /* At now + 25: renewed TTL is now reached */
    struct wheel_node *node = timing_wheel_pop_expired(ctx.wheel, now + 25, &count);
    TEST_ASSERT(count == 1, "registered node must be popped at renewed timestamp");
    TEST_ASSERT(strcmp(node->name, "ingest-test.org") == 0, "domain name must match");

    free(node);
    timing_wheel_destroy(ctx.wheel);
    return true;
}

/* ------------------------------------------------------------------------- */
/* 7. Test Dual-Watermark Math Calculation                                    */
/* ------------------------------------------------------------------------- */
static bool test_dual_watermark_math(void) {
    printf("[TEST] Governance: Dual-Watermark Threshold Calculations\n");

    uint32_t capacity = 2000000;
    uint32_t high_pct = 90;
    uint32_t low_pct = 80;

    uint32_t high_watermark = (capacity * high_pct) / 100;
    uint32_t low_watermark  = (capacity * low_pct) / 100;

    TEST_ASSERT(high_watermark == 1800000, "high watermark must be 1,800,000");
    TEST_ASSERT(low_watermark == 1600000, "low watermark must be 1,600,000");

    /* Simulated saturation: occupancy at 1,850,000 */
    uint64_t current_occ = 1850000;
    TEST_ASSERT(current_occ > high_watermark, "watermark must trigger");

    uint32_t needed_evictions = (uint32_t)(current_occ - low_watermark);
    TEST_ASSERT(needed_evictions == 250000, "needed evictions must be exactly 250,000");

    return true;
}

/* ------------------------------------------------------------------------- */
/* 8. Test In-DRAM Hash Index Key Deduplication & Eviction Prevention       */
/* ------------------------------------------------------------------------- */
static bool test_timing_wheel_deduplication(void) {
    printf("[TEST] Timing Wheel: In-DRAM Hash Deduplication & Eviction Prevention\n");

    struct timing_wheel *w = timing_wheel_create(100);
    TEST_ASSERT(w != NULL, "wheel creation failed");

    uint32_t now = 50000;
    w->last_tick = now;

    /* 1. Insert novel key */
    int ret = timing_wheel_insert(w, "duplicate-test.com", now + 10);
    TEST_ASSERT(ret == 0, "initial insert must succeed");
    TEST_ASSERT(w->total_entries == 1, "total_entries must be 1");
    TEST_ASSERT(timing_wheel_contains(w, "duplicate-test.com") == true, "contains must return true");

    /* 2. Re-insert same key with newer TTL (Renewal) */
    ret = timing_wheel_insert(w, "duplicate-test.com", now + 30);
    TEST_ASSERT(ret == 0, "duplicate insert must succeed");
    TEST_ASSERT(w->total_entries == 1, "duplicate insert must NOT increment total_entries");

    /* 3. At now + 15, key should NOT expire (old TTL overridden) */
    uint32_t count = 0;
    struct wheel_node *exp1 = timing_wheel_pop_expired(w, now + 15, &count);
    TEST_ASSERT(exp1 == NULL, "key must not expire at old timestamp");
    TEST_ASSERT(count == 0, "count must be 0");
    TEST_ASSERT(w->total_entries == 1, "total_entries must remain 1");

    /* 4. At now + 35, key should expire */
    struct wheel_node *exp2 = timing_wheel_pop_expired(w, now + 35, &count);
    TEST_ASSERT(exp2 != NULL, "key must expire at renewed timestamp");
    TEST_ASSERT(count == 1, "count must be 1");
    TEST_ASSERT(w->total_entries == 0, "wheel must now be empty");
    TEST_ASSERT(timing_wheel_contains(w, "duplicate-test.com") == false, "contains must return false after expiration");

    free(exp2);

    /* 5. Saturation & eviction avoidance test:
     * Fill wheel to small capacity, insert duplicates, verify victim eviction does NOT trigger */
    uint32_t small_cap = 5;
    struct timing_wheel *w_small = timing_wheel_create(small_cap);
    for (uint32_t i = 0; i < small_cap; i++) {
        char name[64];
        snprintf(name, sizeof(name), "unique-%u.com", i);
        timing_wheel_insert(w_small, name, now + 100 + i);
    }
    TEST_ASSERT(w_small->total_entries == small_cap, "small wheel must be at capacity");

    /* Insert duplicate of unique-0.com: total_entries must remain small_cap */
    timing_wheel_insert(w_small, "unique-0.com", now + 200);
    TEST_ASSERT(w_small->total_entries == small_cap, "duplicate must not increase total_entries");

    timing_wheel_destroy(w);
    timing_wheel_destroy(w_small);
    return true;
}

/* ------------------------------------------------------------------------- */
/* Main Test Runner                                                          */
/* ------------------------------------------------------------------------- */
int main(void) {
    printf("==========================================================\n");
    printf("🧪 Running AtesN-DS Control-Plane Daemon Unit Tests\n");
    printf("==========================================================\n\n");

    bool all_ok = true;
    all_ok &= test_timing_wheel_create_destroy();
    all_ok &= test_timing_wheel_insert();
    all_ok &= test_timing_wheel_pop_expired();
    all_ok &= test_timing_wheel_pop_min_ttl();
    all_ok &= test_hw_key_boundary();
    all_ok &= test_ingest_event_handler();
    all_ok &= test_dual_watermark_math();
    all_ok &= test_timing_wheel_deduplication();

    printf("\n==========================================================\n");
    if (all_ok) {
        printf("🎉 ALL DAEMON UNIT TESTS PASSED! (%d/%d checks passed)\n", tests_passed, tests_run);
        printf("==========================================================\n");
        return 0;
    } else {
        printf("❌ DAEMON UNIT TESTS FAILED (%d/%d passed)\n", tests_passed, tests_run);
        printf("==========================================================\n");
        return 1;
    }
}
