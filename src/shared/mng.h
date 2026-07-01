#ifndef MNG_H
#define MNG_H

#include <stdbool.h>

#include "config.h"
#include "metrics.h"
#include "selector.h"
#include "users.h"

void mng_set_context(const char *admin_secret, users_t *users,
                     metrics_t *metrics, config_t *config);
void mng_passive_accept(struct selector_key *key);
unsigned mng_active_sessions(void);
void mng_pool_destroy(void);

#endif
