#include <stddef.h>
#include "access_log.h"

access_log_t *
access_log_create(const char *path)
{
    (void)path;
    return NULL;
}

void
access_log_destroy(access_log_t *log)
{
    (void)log;
}

void
access_log_open(access_log_t *log, const char *user, const char *dest, uint16_t port)
{
    (void)log;
    (void)user;
    (void)dest;
    (void)port;
}

void
access_log_close(access_log_t *log, const char *user, const char *dest, uint16_t port,
                uint64_t bytes_c2o, uint64_t bytes_o2c)
{
    (void)log;
    (void)user;
    (void)dest;
    (void)port;
    (void)bytes_c2o;
    (void)bytes_o2c;
}

void
access_log_fail(access_log_t *log, const char *user, const char *dest, uint16_t port,
                const char *reason)
{
    (void)log;
    (void)user;
    (void)dest;
    (void)port;
    (void)reason;
}
