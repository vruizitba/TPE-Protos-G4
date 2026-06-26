#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>

typedef struct config {
    bool dissectors_enabled;
    int negotiation_timeout;  /* seconds, 0 = disabled */
    int connect_timeout;      /* seconds, 0 = disabled */
    int idle_timeout;         /* seconds, 0 = disabled */
    int max_connections;      /* 0 = unlimited */
} config_t;

void config_init(config_t *c);

#endif
