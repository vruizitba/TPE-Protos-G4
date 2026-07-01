#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>

typedef struct config {
    int negotiation_timeout;  /* seconds, 0 = disabled */
    int connect_timeout;      /* seconds, 0 = disabled */
    int idle_timeout;         /* seconds, 0 = disabled */
    int max_connections;      /* 0 = unlimited */
} config_t;

void config_init(config_t *c);
void config_set_defaults(config_t *c, int negotiation_timeout, int connect_timeout,
                         int idle_timeout, int max_connections);

bool config_set_key(config_t *c, const char *key, int value);
bool config_get_key(const config_t *c, const char *key, int *value);
bool config_is_key(const char *key);

#endif
