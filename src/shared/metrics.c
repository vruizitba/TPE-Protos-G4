#include <stddef.h>
#include "metrics.h"

metrics_t *
metrics_create(void)
{
    return NULL;
}

void
metrics_destroy(metrics_t *m)
{
    (void)m;
}

void
metrics_conn_accepted(metrics_t *m)
{
    (void)m;
}

void
metrics_conn_closed(metrics_t *m)
{
    (void)m;
}

void
metrics_conn_rejected(metrics_t *m)
{
    (void)m;
}

void
metrics_auth_fail(metrics_t *m)
{
    (void)m;
}

void
metrics_origin_ok(metrics_t *m)
{
    (void)m;
}

void
metrics_origin_fail(metrics_t *m)
{
    (void)m;
}

void
metrics_add_bytes_c2o(metrics_t *m, uint64_t n)
{
    (void)m;
    (void)n;
}

void
metrics_add_bytes_o2c(metrics_t *m, uint64_t n)
{
    (void)m;
    (void)n;
}

void
metrics_admin_session_open(metrics_t *m)
{
    (void)m;
}

void
metrics_admin_session_close(metrics_t *m)
{
    (void)m;
}

metrics_snapshot_t
metrics_snapshot(metrics_t *m)
{
    (void)m;
    metrics_snapshot_t s = {0};
    return s;
}
