#ifndef METRICS_H
#define METRICS_H

#include <stdint.h>

typedef struct metrics metrics_t;

metrics_t *metrics_create(void);
void metrics_destroy(metrics_t *m);

void metrics_conn_accepted(metrics_t *m);
void metrics_conn_closed(metrics_t *m);
void metrics_conn_rejected(metrics_t *m);
void metrics_auth_fail(metrics_t *m);
void metrics_origin_ok(metrics_t *m);
void metrics_origin_fail(metrics_t *m);
void metrics_add_bytes_c2o(metrics_t *m, uint64_t n);
void metrics_add_bytes_o2c(metrics_t *m, uint64_t n);
void metrics_admin_session_open(metrics_t *m);
void metrics_admin_session_close(metrics_t *m);

/* Snapshot for reporting */
typedef struct {
    uint64_t conn_accepted;
    uint64_t conn_active;
    uint64_t conn_rejected;
    uint64_t auth_fail;
    uint64_t origin_ok;
    uint64_t origin_fail;
    uint64_t bytes_c2o;
    uint64_t bytes_o2c;
    uint64_t admin_sessions;
} metrics_snapshot_t;

metrics_snapshot_t metrics_snapshot(metrics_t *m);

#endif
