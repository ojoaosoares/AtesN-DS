#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include "daemon_timing_wheel.h"

struct timing_wheel *timing_wheel_create(uint32_t capacity) {
    struct timing_wheel *w = calloc(1, sizeof(struct timing_wheel));
    if (!w) return NULL;

    w->capacity = capacity ? capacity : WHEEL_SECONDS_CAPACITY;
    w->buckets = calloc(w->capacity, sizeof(struct wheel_node *));
    if (!w->buckets) {
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
    pthread_mutex_unlock(&w->lock);
    pthread_mutex_destroy(&w->lock);
    free(w);
}

int timing_wheel_insert(struct timing_wheel *w, const char *name, uint32_t expire_time) {
    struct wheel_node *node = malloc(sizeof(struct wheel_node));
    if (!node) return -ENOMEM;

    memcpy(node->name, name, MAX_DNS_NAME_LENGTH_HW);
    node->expire_time = expire_time;

    uint32_t bucket = expire_time % w->capacity;

    pthread_mutex_lock(&w->lock);
    node->next = w->buckets[bucket];
    w->buckets[bucket] = node;
    w->total_entries++;
    pthread_mutex_unlock(&w->lock);

    return 0;
}

struct wheel_node *timing_wheel_pop_expired(struct timing_wheel *w, uint32_t current_time, uint32_t *count) {
    struct wheel_node *expired_head = NULL;
    uint32_t popped = 0;

    pthread_mutex_lock(&w->lock);
    if (w->last_tick == 0) w->last_tick = current_time;

    /* Drain all buckets from last_tick up to current_time */
    for (uint32_t t = w->last_tick; t <= current_time; t++) {
        uint32_t bucket = t % w->capacity;
        struct wheel_node *cur = w->buckets[bucket];
        struct wheel_node *prev = NULL;

        while (cur) {
            struct wheel_node *next = cur->next;
            if (cur->expire_time <= current_time) {
                if (prev) {
                    prev->next = next;
                } else {
                    w->buckets[bucket] = next;
                }
                cur->next = expired_head;
                expired_head = cur;
                popped++;
                if (w->total_entries > 0) w->total_entries--;
            } else {
                prev = cur;
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
    struct wheel_node *evict_head = NULL;
    uint32_t evicted = 0;

    pthread_mutex_lock(&w->lock);
    /* Walk forward starting from current_time until target_evict is reached */
    for (uint32_t offset = 1; offset < w->capacity && evicted < target_evict; offset++) {
        uint32_t bucket = (current_time + offset) % w->capacity;
        struct wheel_node *cur = w->buckets[bucket];
        while (cur && evicted < target_evict) {
            struct wheel_node *next = cur->next;
            w->buckets[bucket] = next;

            cur->next = evict_head;
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
