#ifndef DAEMON_PREFETCH_H
#define DAEMON_PREFETCH_H

#include "daemon_context.h"

int build_dns_query(char *buf, size_t buf_size, uint16_t id, const char *domain);
int send_dns_query_from_ip(__u32 src_ip, __u16 src_port, __u32 dst_ip, uint16_t id, const char *domain);
int handle_resolver_sample(void *ctx, void *data, size_t len);
void *resolver_worker_thread(void *arg);

#endif /* DAEMON_PREFETCH_H */
