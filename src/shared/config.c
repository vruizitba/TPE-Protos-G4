#include <string.h>
#include "config.h"

void
config_init(config_t *c)
{
    memset(c, 0, sizeof(*c));
}

void
config_set_defaults(config_t *c, int negotiation_timeout, int connect_timeout,
                    int idle_timeout, int max_connections)
{
    c->negotiation_timeout = negotiation_timeout;
    c->connect_timeout = connect_timeout;
    c->idle_timeout = idle_timeout;
    c->max_connections = max_connections;
}

bool
config_set_key(config_t *c, const char *key, int value)
{
    if (value < 0 || key == NULL) {
        return false;
    }
    if (strcmp(key, "negotiation-timeout") == 0) {
        c->negotiation_timeout = value;
    } else if (strcmp(key, "connect-timeout") == 0) {
        c->connect_timeout = value;
    } else if (strcmp(key, "idle-timeout") == 0) {
        c->idle_timeout = value;
    } else if (strcmp(key, "max-connections") == 0) {
        c->max_connections = value;
    } else {
        return false;
    }
    return true;
}

bool
config_get_key(const config_t *c, const char *key, int *value)
{
    if (c == NULL || key == NULL || value == NULL) {
        return false;
    }
    if (strcmp(key, "negotiation-timeout") == 0) {
        *value = c->negotiation_timeout;
    } else if (strcmp(key, "connect-timeout") == 0) {
        *value = c->connect_timeout;
    } else if (strcmp(key, "idle-timeout") == 0) {
        *value = c->idle_timeout;
    } else if (strcmp(key, "max-connections") == 0) {
        *value = c->max_connections;
    } else {
        return false;
    }
    return true;
}

bool
config_is_key(const char *key)
{
    int ignored;
    config_t empty;
    config_init(&empty);
    return config_get_key(&empty, key, &ignored);
}
