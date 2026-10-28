#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include "daemon_timing_wheel.h"

/* FNV-1a 32-bit hash for 56-byte zero-padded hardware keys */
static inline uint32_t timing_wheel_hash_name(const char *name) {
    uint32_t hash = 2166136261u;
    const uint8_t *p = (const uint8_t *)name;
    for (size_t i = 0; i < MAX_DNS_NAME_LENGTH_HW; i++) {
        hash ^= p[i];
        hash *= 16777619u;
    }
    return hash;
}

/* Ensure clean 56-byte buffer: copies wire or string format, zero-pads the rest */
static inline void timing_wheel_normalize_name(char *dst, const char *src) {
    memset(dst, 0, MAX_DNS_NAME_LENGTH_HW);
    size_t i = 0;
    while (i < MAX_DNS_NAME_LENGTH_HW && src[i] != '\0') {
        dst[i] = src[i];
        i++;
    }
    if (i < MAX_DNS_NAME_LENGTH_HW) {
        dst[i] = '\0';
    }
}

/* Must be called with w->lock held */
static struct wheel_node *timing_wheel_lookup_locked(struct timing_wheel *w, const char *norm_name) {
    if (!w || !w->hash_table) return NULL;
    uint32_t h = timing_wheel_hash_name(norm_name) & w->hash_mask;
    struct wheel_node *cur = w->hash_table[h];
    while (cur) {
        if (memcmp(cur->name, norm_name, MAX_DNS_NAME_LENGTH_HW) == 0) {
            return cur;
        }
        cur = cur->hash_next;
    }
    return NULL;
}

/* Unlink node from its time bucket (must be called with w->lock held) */
static void timing_wheel_unlink_time(struct timing_wheel *w, struct wheel_node *node) {
    uint32_t bucket = node->expire_time % w->capacity;
    if (node->prev) {
        node->prev->next = node->next;
    } else if (w->buckets[bucket] == node) {
        w->buckets[bucket] = node->next;
    }
    if (node->next) {
        node->next->prev = node->prev;
    }
    node->next = NULL;
    node->prev = NULL;
}

/* Unlink node from hash bucket (must be called with w->lock held) */
static void timing_wheel_unlink_hash(struct timing_wheel *w, struct wheel_node *node) {
    uint32_t h = timing_wheel_hash_name(node->name) & w->hash_mask;
    if (node->hash_prev) {
        node->hash_prev->hash_next = node->hash_next;
    } else if (w->hash_table[h] == node) {
        w->hash_table[h] = node->hash_next;
    }
    if (node->hash_next) {
        node->hash_next->hash_prev = node->hash_prev;
    }
    node->hash_next = NULL;
    node->hash_prev = NULL;
}

/* Link node into its time bucket (must be called with w->lock held) */
static void timing_wheel_link_time(struct timing_wheel *w, struct wheel_node *node) {
    uint32_t bucket = node->expire_time % w->capacity;
    node->next = w->buckets[bucket];
    node->prev = NULL;
    if (w->buckets[bucket]) {
        w->buckets[bucket]->prev = node;
    }
    w->buckets[bucket] = node;
}

/* Link node into hash bucket (must be called with w->lock held) */
static void timing_wheel_link_hash(struct timing_wheel *w, struct wheel_node *node) {
    uint32_t h = timing_wheel_hash_name(node->name) & w->hash_mask;
    node->hash_next = w->hash_table[h];
    node->hash_prev = NULL;
    if (w->hash_table[h]) {
        w->hash_table[h]->hash_prev = node;
    }
    w->hash_table[h] = node;
}

struct timing_wheel *timing_wheel_create(uint32_t capacity) {
    struct timing_wheel *w = calloc(1, sizeof(struct timing_wheel));
    if (!w) return NULL;

    w->capacity = capacity ? capacity : WHEEL_SECONDS_CAPACITY;
    w->buckets = calloc(w->capacity, sizeof(struct wheel_node *));
    if (!w->buckets) {
        free(w);
        return NULL;
    }

    w->hash_size = TIMING_WHEEL_HASH_SIZE;
    w->hash_mask = TIMING_WHEEL_HASH_MASK;
    w->hash_table = calloc(w->hash_size, sizeof(struct wheel_node *));
    if (!w->hash_table) {
        free(w->buckets);
        free(w);
        return NULL;
    }

    pthread_mutex_init(&w->lock, NULL);
    w->last_tick = (uint32_t)time(NULL);
    w->total_entries = 0;
    return w;
}

void timing_wheel_destroy(struct timing_wheel *w) {
    if (!w) return;
    pthread_mutex_lock(&w->lock);
    for (uint32_t i = 0; i < w->capacity; i++) {
        struct wheel_node *cur = w->buckets[i];
        while (cur) {
            struct wheel_node *tmp = cur;
            cur = cur->next;
            free(tmp);
        }
    }
    free(w->buckets);
    free(w->hash_table);
    pthread_mutex_unlock(&w->lock);
    pthread_mutex_destroy(&w->lock);
    free(w);
}

void timing_wheel_clear(struct timing_wheel *w) {
    if (!w) return;
    pthread_mutex_lock(&w->lock);
    for (uint32_t i = 0; i < w->capacity; i++) {
        struct wheel_node *cur = w->buckets[i];
        while (cur) {
            struct wheel_node *tmp = cur;
            cur = cur->next;
            free(tmp);
        }
        w->buckets[i] = NULL;
    }
    if (w->hash_table) {
        memset(w->hash_table, 0, w->hash_size * sizeof(struct wheel_node *));
    }
    w->total_entries = 0;
    w->last_tick = 0;
    pthread_mutex_unlock(&w->lock);
}

int timing_wheel_insert(struct timing_wheel *w, const char *name, uint32_t expire_time) {
    if (!w) return -EINVAL;
    char norm[MAX_DNS_NAME_LENGTH_HW];
    timing_wheel_normalize_name(norm, name);

    pthread_mutex_lock(&w->lock);
    struct wheel_node *existing = timing_wheel_lookup_locked(w, norm);
    if (existing) {
        /* Domain already exists: update expiration time and move to new time bucket */
        timing_wheel_unlink_time(w, existing);
        existing->expire_time = expire_time;
        timing_wheel_link_time(w, existing);
        pthread_mutex_unlock(&w->lock);
        return 0;
    }

    /* Brand new domain: allocate and insert into both time wheel and hash table */
    struct wheel_node *node = calloc(1, sizeof(struct wheel_node));
    if (!node) {
        pthread_mutex_unlock(&w->lock);
        return -ENOMEM;
    }

    memcpy(node->name, norm, MAX_DNS_NAME_LENGTH_HW);
    node->expire_time = expire_time;

    timing_wheel_link_time(w, node);
    timing_wheel_link_hash(w, node);
    w->total_entries++;
    pthread_mutex_unlock(&w->lock);

    return 0;
}

int timing_wheel_update_expire(struct timing_wheel *w, const char *name, uint32_t new_expire_time) {
    if (!w) return -EINVAL;
    char norm[MAX_DNS_NAME_LENGTH_HW];
    timing_wheel_normalize_name(norm, name);

    pthread_mutex_lock(&w->lock);
    struct wheel_node *existing = timing_wheel_lookup_locked(w, norm);
    if (!existing) {
        pthread_mutex_unlock(&w->lock);
        return -ENOENT;
    }

    timing_wheel_unlink_time(w, existing);
    existing->expire_time = new_expire_time;
    timing_wheel_link_time(w, existing);
    pthread_mutex_unlock(&w->lock);

    return 0;
}

bool timing_wheel_contains(struct timing_wheel *w, const char *name) {
    if (!w) return false;
    char norm[MAX_DNS_NAME_LENGTH_HW];
    timing_wheel_normalize_name(norm, name);

    pthread_mutex_lock(&w->lock);
    bool found = (timing_wheel_lookup_locked(w, norm) != NULL);
    pthread_mutex_unlock(&w->lock);

    return found;
}

struct wheel_node *timing_wheel_find(struct timing_wheel *w, const char *name) {
    if (!w) return NULL;
    char norm[MAX_DNS_NAME_LENGTH_HW];
    timing_wheel_normalize_name(norm, name);

    pthread_mutex_lock(&w->lock);
    struct wheel_node *node = timing_wheel_lookup_locked(w, norm);
    pthread_mutex_unlock(&w->lock);

    return node;
}

struct wheel_node *timing_wheel_pop_expired(struct timing_wheel *w, uint32_t current_time, uint32_t *count) {
    if (!w) {
        if (count) *count = 0;
        return NULL;
    }

    struct wheel_node *expired_head = NULL;
    uint32_t popped = 0;

    pthread_mutex_lock(&w->lock);
    if (w->last_tick == 0 || current_time < w->last_tick) {
        w->last_tick = current_time;
    }

    /* Prevent iterating more than capacity if system lagged */
    uint32_t ticks = current_time - w->last_tick;
    if (ticks >= w->capacity) {
        w->last_tick = current_time - w->capacity + 1;
    }

    /* Drain all buckets from last_tick up to current_time */
    for (uint32_t t = w->last_tick; t <= current_time; t++) {
        uint32_t bucket = t % w->capacity;
        struct wheel_node *cur = w->buckets[bucket];

        while (cur) {
            struct wheel_node *next = cur->next;
            if (cur->expire_time <= current_time) {
                timing_wheel_unlink_time(w, cur);
                timing_wheel_unlink_hash(w, cur);

                cur->next = expired_head;
                cur->prev = NULL;
                expired_head = cur;
                popped++;
                if (w->total_entries > 0) w->total_entries--;
            }
            cur = next;
        }
    }
    w->last_tick = current_time + 1;
    pthread_mutex_unlock(&w->lock);

    if (count) *count = popped;
    return expired_head;
}

struct wheel_node *timing_wheel_pop_min_ttl(struct timing_wheel *w, uint32_t current_time,
                                           uint32_t target_evict, uint32_t *count) {
    if (!w || target_evict == 0) {
        if (count) *count = 0;
        return NULL;
    }

    struct wheel_node *evict_head = NULL;
    uint32_t evicted = 0;

    pthread_mutex_lock(&w->lock);
    /* Walk forward starting from current_time until target_evict is reached */
    for (uint32_t offset = 1; offset < w->capacity && evicted < target_evict; offset++) {
        uint32_t bucket = (current_time + offset) % w->capacity;
        struct wheel_node *cur = w->buckets[bucket];
        while (cur && evicted < target_evict) {
            struct wheel_node *next = cur->next;
            timing_wheel_unlink_time(w, cur);
            timing_wheel_unlink_hash(w, cur);

            cur->next = evict_head;
            cur->prev = NULL;
            evict_head = cur;
            evicted++;
            if (w->total_entries > 0) w->total_entries--;
            cur = next;
        }
    }
    pthread_mutex_unlock(&w->lock);

    if (count) *count = evicted;
    return evict_head;
}

struct wheel_node *timing_wheel_pop_victims(struct timing_wheel *w, uint32_t current_time,
                                            uint32_t target_count, uint32_t *count) {
    if (!w || target_count == 0) {
        if (count) *count = 0;
        return NULL;
    }

    struct wheel_node *head = NULL;
    uint32_t popped = 0;

    pthread_mutex_lock(&w->lock);
    if (w->total_entries == 0) {
        pthread_mutex_unlock(&w->lock);
        if (count) *count = 0;
        return NULL;
    }

    if (w->last_tick == 0 || current_time < w->last_tick) {
        w->last_tick = current_time;
    }

    uint32_t ticks = current_time - w->last_tick;
    if (ticks >= w->capacity) {
        w->last_tick = current_time - w->capacity + 1;
    }

    /* Phase 1: Pop expired entries from last_tick up to current_time */
    for (uint32_t t = w->last_tick; t <= current_time && popped < target_count; t++) {
        uint32_t bucket = t % w->capacity;
        struct wheel_node *cur = w->buckets[bucket];

        while (cur && popped < target_count) {
            struct wheel_node *next = cur->next;
            if (cur->expire_time <= current_time) {
                timing_wheel_unlink_time(w, cur);
                timing_wheel_unlink_hash(w, cur);

                cur->next = head;
                cur->prev = NULL;
                head = cur;
                popped++;
                if (w->total_entries > 0) w->total_entries--;
            }
            cur = next;
        }
        if (!w->buckets[bucket]) {
            w->last_tick = t + 1;
        }
    }

    /* Phase 2: If target not yet met, pop entries with earliest future expiration (min-TTL) */
    if (popped < target_count) {
        for (uint32_t offset = 1; offset < w->capacity && popped < target_count; offset++) {
            uint32_t bucket = (current_time + offset) % w->capacity;
            struct wheel_node *cur = w->buckets[bucket];
            while (cur && popped < target_count) {
                struct wheel_node *next = cur->next;
                timing_wheel_unlink_time(w, cur);
                timing_wheel_unlink_hash(w, cur);

                cur->next = head;
                cur->prev = NULL;
                head = cur;
                popped++;
                if (w->total_entries > 0) w->total_entries--;
                cur = next;
            }
        }
    }

    pthread_mutex_unlock(&w->lock);
    if (count) *count = popped;
    return head;
}
