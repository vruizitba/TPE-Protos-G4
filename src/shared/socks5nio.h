#ifndef SOCKS5NIO_H
#define SOCKS5NIO_H

#include "selector.h"
#include "users.h"
#include "metrics.h"

void socksv5_passive_accept(struct selector_key *key);
unsigned socksv5_active_sessions(void);
void socksv5_pool_destroy(void);
void socksv5_set_users(users_t *u);
void socksv5_set_metrics(metrics_t *m);

#endif
