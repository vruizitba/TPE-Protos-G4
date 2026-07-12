#ifndef SOCKS5NIO_H
#define SOCKS5NIO_H

#include "selector.h"
#include "users.h"
#include "metrics.h"
#include "dns_worker.h"
#include "access_log.h"
#include "config.h"

void socksv5_passive_accept(struct selector_key *key);
unsigned socksv5_active_sessions(void);
void socksv5_pool_destroy(void);
void socksv5_set_users(users_t *u);
void socksv5_set_metrics(metrics_t *m);
void socksv5_set_dns_worker(dns_worker_t *w);
void socksv5_set_access_log(access_log_t *log);
void socksv5_set_config(config_t *c);
void socksv5_check_timeouts(fd_selector s);

#endif
