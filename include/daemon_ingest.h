#ifndef DAEMON_INGEST_H
#define DAEMON_INGEST_H

#include "daemon_context.h"

int handle_hw_sync_sample(void *ctx, void *data, size_t len);
void *ingest_worker_thread(void *arg);

#endif /* DAEMON_INGEST_H */
