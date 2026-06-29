#ifndef DNS_WORKER_H
#define DNS_WORKER_H

#include <stdint.h>
#include <netdb.h>
#include "selector.h"

typedef struct dns_worker dns_worker_t;

dns_worker_t *dns_worker_create(void);
void dns_worker_destroy(dns_worker_t *w);

/*
 * Submits a DNS resolution job. When getaddrinfo completes, the result
 * is stored in *result_target and selector_notify_block(selector, fd) is called.
 * Returns 0 on success, -1 on allocation failure.
 */
int dns_worker_submit(dns_worker_t *w, int fd, const char *host, uint16_t port,
                      struct addrinfo **result_target, fd_selector selector);

#endif
