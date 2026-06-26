#ifndef ACCESS_LOG_H
#define ACCESS_LOG_H

#include <stdint.h>

typedef struct access_log access_log_t;

access_log_t *access_log_create(const char *path); /* NULL = stderr */
void access_log_destroy(access_log_t *log);

void access_log_open(access_log_t *log, const char *user, const char *dest, uint16_t port);

void access_log_close(access_log_t *log, const char *user, const char *dest, uint16_t port,
                        uint64_t bytes_c2o, uint64_t bytes_o2c);

void access_log_fail(access_log_t *log, const char *user, const char *dest, uint16_t port,
                        const char *reason);

#endif
