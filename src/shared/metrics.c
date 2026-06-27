#include <stdlib.h>
#include "metrics.h"

struct metrics {
    uint64_t conn_accepted;
    uint64_t conn_closed;
    uint64_t conn_rejected;
    uint64_t auth_fail;
    uint64_t origin_ok;
    uint64_t origin_fail;
    uint64_t bytes_c2o;
    uint64_t bytes_o2c;
    uint64_t admin_sessions;
};

metrics_t *metrics_create(void) {
    return calloc(1, sizeof(metrics_t));
}

void metrics_destroy(metrics_t *m) {
    free(m);
}

void metrics_conn_accepted(metrics_t *m) {
    m->conn_accepted++;
}

void metrics_conn_closed(metrics_t *m) {
    m->conn_closed++;
}

void metrics_conn_rejected(metrics_t *m) {
    m->conn_rejected++;
}

void metrics_auth_fail(metrics_t *m) {
    m->auth_fail++;
}

void metrics_origin_ok(metrics_t *m) {
    m->origin_ok++;
}

void metrics_origin_fail(metrics_t *m) {
    m->origin_fail++;
}

void metrics_add_bytes_c2o(metrics_t *m, uint64_t n) {
    m->bytes_c2o += n;
}

void metrics_add_bytes_o2c(metrics_t *m, uint64_t n) {
    m->bytes_o2c += n;
}

void metrics_admin_session_open(metrics_t *m) {
    m->admin_sessions++;
}

void metrics_admin_session_close(metrics_t *m) {
    if (m->admin_sessions > 0) {
        m->admin_sessions--;
    }
}

metrics_snapshot_t metrics_snapshot(metrics_t *m) {
    metrics_snapshot_t s = {
        .conn_accepted = m->conn_accepted,
        .conn_active = m->conn_accepted - m->conn_closed,
        .conn_rejected = m->conn_rejected,
        .auth_fail = m->auth_fail,
        .origin_ok = m->origin_ok,
        .origin_fail = m->origin_fail,
        .bytes_c2o = m->bytes_c2o,
        .bytes_o2c = m->bytes_o2c,
        .admin_sessions = m->admin_sessions,
    };
    return s;
}
