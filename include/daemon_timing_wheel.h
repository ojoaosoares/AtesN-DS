#ifndef DAEMON_TIMING_WHEEL_H
#define DAEMON_TIMING_WHEEL_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include "dns.h"

#define WHEEL_SECONDS_CAPACITY 86400  /* 24-hour timing wheel horizon */
#define TIMING_WHEEL_HASH_SIZE 131072 /* 128k buckets for fast O(1) deduplication */
#define TIMING_WHEEL_HASH_MASK (TIMING_WHEEL_HASH_SIZE - 1)

struct wheel_node {
    char name[MAX_DNS_NAME_LENGTH_HW];
    uint32_t expire_time;
    struct wheel_node *next;        /* next in time bucket OR popped list head */
    struct wheel_node *prev;        /* prev in time bucket */
    struct wheel_node *hash_next;   /* next in domain hash bucket */
    struct wheel_node *hash_prev;   /* prev in domain hash bucket */
};

struct timing_wheel {
    struct wheel_node **buckets;
    uint32_t capacity;
    struct wheel_node **hash_table;
    uint32_t hash_size;
    uint32_t hash_mask;
    uint64_t total_entries;
    uint32_t last_tick;
    pthread_mutex_t lock;
};

struct timing_wheel *timing_wheel_create(uint32_t capacity);
void timing_wheel_destroy(struct timing_wheel *w);
void timing_wheel_clear(struct timing_wheel *w);
int timing_wheel_insert(struct timing_wheel *w, const char *name, uint32_t expire_time);
int timing_wheel_update_expire(struct timing_wheel *w, const char *name, uint32_t new_expire_time);
bool timing_wheel_contains(struct timing_wheel *w, const char *name);
struct wheel_node *timing_wheel_find(struct timing_wheel *w, const char *name);
struct wheel_node *timing_wheel_pop_expired(struct timing_wheel *w, uint32_t current_time, uint32_t *count);
struct wheel_node *timing_wheel_pop_min_ttl(struct timing_wheel *w, uint32_t current_time, uint32_t target_evict, uint32_t *count);
struct wheel_node *timing_wheel_pop_victims(struct timing_wheel *w, uint32_t current_time, uint32_t target_count, uint32_t *count);

#endif /* DAEMON_TIMING_WHEEL_H */
