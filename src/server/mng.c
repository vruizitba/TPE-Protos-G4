#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include <sys/socket.h>
#include <unistd.h>

#include "mng.h"

#define MNG_LINE_SIZE 1024
#define MNG_WRITE_SIZE 4096
#define MNG_MAX_AUTH_FAILURES 3

struct mng_session {
    int fd;
    char line[MNG_LINE_SIZE];
    size_t line_len;
    char in_buf[256];
    size_t in_len;
    size_t in_pos;
    char out[MNG_WRITE_SIZE];
    size_t out_len;
    size_t out_sent;
    bool authenticated;
    bool locked;
    bool closing;
    unsigned auth_failures;
};

static const char *g_admin_secret;
static users_t *g_users;
static metrics_t *g_metrics;
static config_t *g_config;
static unsigned g_active_sessions;

static void mng_read(struct selector_key *key);
static void mng_write(struct selector_key *key);
static void mng_close(struct selector_key *key);

static const struct fd_handler mng_handler = {
    .handle_read = mng_read,
    .handle_write = mng_write,
    .handle_close = mng_close,
};

void
mng_set_context(const char *admin_secret, users_t *users,
                metrics_t *metrics, config_t *config)
{
    g_admin_secret = admin_secret;
    g_users = users;
    g_metrics = metrics;
    g_config = config;
}

static void
trim_right(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && isspace((unsigned char)s[n - 1])) {
        s[--n] = '\0';
    }
}

static char *
next_token(char **cursor)
{
    char *s = *cursor;
    while (*s != '\0' && isspace((unsigned char)*s)) {
        s++;
    }
    if (*s == '\0') {
        *cursor = s;
        return NULL;
    }
    char *start = s;
    while (*s != '\0' && !isspace((unsigned char)*s)) {
        s++;
    }
    if (*s != '\0') {
        *s++ = '\0';
    }
    *cursor = s;
    return start;
}

static bool
parse_nonnegative(const char *s, int *value)
{
    char *end = NULL;
    long n;

    if (s == NULL || *s == '\0') {
        return false;
    }
    errno = 0;
    n = strtol(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || n < 0 || n > INT32_MAX) {
        return false;
    }
    *value = (int)n;
    return true;
}

static void
queue_response(struct selector_key *key, const char *fmt, ...)
{
    struct mng_session *session = key->data;
    va_list args;
    int n;

    va_start(args, fmt);
    n = vsnprintf(session->out, sizeof(session->out), fmt, args);
    va_end(args);

    if (n < 0) {
        session->out_len = 0;
    } else if ((size_t)n >= sizeof(session->out)) {
        static const char truncated[] = "-ERR response too large\n";
        memcpy(session->out, truncated, sizeof(truncated) - 1);
        session->out_len = sizeof(truncated) - 1;
    } else {
        session->out_len = (size_t)n;
    }
    session->out_sent = 0;
    selector_set_interest_key(key, OP_WRITE);
}

static bool
require_auth(struct selector_key *key, const struct mng_session *session)
{
    if (session->locked) {
        queue_response(key, "-ERR locked\n");
        return false;
    }
    if (!session->authenticated) {
        queue_response(key, "-ERR auth required\n");
        return false;
    }
    return true;
}

static void
handle_auth(struct selector_key *key, struct mng_session *session, char **cursor)
{
    char *secret = next_token(cursor);
    char *extra = next_token(cursor);

    if (secret == NULL || extra != NULL) {
        queue_response(key, "-ERR usage AUTH <secret>\n");
        return;
    }
    if (g_admin_secret == NULL || *g_admin_secret == '\0') {
        queue_response(key, "-ERR auth required\n");
        return;
    }
    if (strcmp(secret, g_admin_secret) == 0) {
        session->authenticated = true;
        session->auth_failures = 0;
        queue_response(key, "+OK authenticated\n");
        return;
    }

    session->auth_failures++;
    if (session->auth_failures >= MNG_MAX_AUTH_FAILURES) {
        session->locked = true;
        session->closing = true;
        queue_response(key, "-ERR locked\n");
    } else {
        queue_response(key, "-ERR invalid credentials\n");
    }
}

static void
handle_stats(struct selector_key *key)
{
    metrics_snapshot_t s;

    if (g_metrics == NULL) {
        queue_response(key, "-ERR metrics unavailable\n");
        return;
    }
    s = metrics_snapshot(g_metrics);
    queue_response(key,
                   "+OK conn-accepted=%" PRIu64 " conn-active=%" PRIu64
                   " conn-rejected=%" PRIu64 " auth-fail=%" PRIu64
                   " origin-ok=%" PRIu64 " origin-fail=%" PRIu64
                   " bytes-c2o=%" PRIu64 " bytes-o2c=%" PRIu64
                   " admin-sessions=%" PRIu64 "\n",
                   s.conn_accepted, s.conn_active, s.conn_rejected,
                   s.auth_fail, s.origin_ok, s.origin_fail, s.bytes_c2o,
                   s.bytes_o2c, s.admin_sessions);
}

static void
handle_users(struct selector_key *key)
{
    size_t used;
    int count;

    if (g_users == NULL) {
        queue_response(key, "-ERR users unavailable\n");
        return;
    }
    count = users_count(g_users);
    used = (size_t)snprintf(((struct mng_session *)key->data)->out,
                            MNG_WRITE_SIZE, "+OK users=");
    if (count == 0) {
        queue_response(key, "+OK users=-\n");
        return;
    }
    for (int i = 0; i < count; i++) {
        const char *name = users_get_name(g_users, i);
        int n = snprintf(((struct mng_session *)key->data)->out + used,
                         MNG_WRITE_SIZE - used, "%s%s",
                         i == 0 ? "" : ",", name == NULL ? "" : name);
        if (n < 0 || used + (size_t)n >= MNG_WRITE_SIZE) {
            queue_response(key, "-ERR response too large\n");
            return;
        }
        used += (size_t)n;
    }
    if (used + 1 >= MNG_WRITE_SIZE) {
        queue_response(key, "-ERR response too large\n");
        return;
    }
    ((struct mng_session *)key->data)->out[used++] = '\n';
    ((struct mng_session *)key->data)->out[used] = '\0';
    ((struct mng_session *)key->data)->out_len = used;
    ((struct mng_session *)key->data)->out_sent = 0;
    selector_set_interest_key(key, OP_WRITE);
}

static void
handle_user(struct selector_key *key, char **cursor)
{
    char *action = next_token(cursor);

    if (g_users == NULL) {
        queue_response(key, "-ERR users unavailable\n");
    } else if (action == NULL) {
        queue_response(key, "-ERR usage USER SET <name> <pass> | USER DELETE <name>\n");
    } else if (strcmp(action, "SET") == 0) {
        char *name = next_token(cursor);
        char *pass = next_token(cursor);
        char *extra = next_token(cursor);
        if (name == NULL || pass == NULL || extra != NULL) {
            queue_response(key, "-ERR usage USER SET <name> <pass>\n");
        } else if (users_add(g_users, name, pass)) {
            queue_response(key, "+OK user set\n");
        } else {
            queue_response(key, "-ERR user limit reached\n");
        }
    } else if (strcmp(action, "DELETE") == 0) {
        char *name = next_token(cursor);
        char *extra = next_token(cursor);
        if (name == NULL || extra != NULL) {
            queue_response(key, "-ERR usage USER DELETE <name>\n");
        } else if (users_del(g_users, name)) {
            queue_response(key, "+OK user deleted\n");
        } else {
            queue_response(key, "-ERR user not found\n");
        }
    } else {
        queue_response(key, "-ERR unknown USER command\n");
    }
}

static void
handle_config_get(struct selector_key *key)
{
    if (g_config == NULL) {
        queue_response(key, "-ERR config unavailable\n");
        return;
    }
    queue_response(key,
                   "+OK negotiation-timeout=%d connect-timeout=%d "
                   "idle-timeout=%d max-connections=%d\n",
                   g_config->negotiation_timeout, g_config->connect_timeout,
                   g_config->idle_timeout, g_config->max_connections);
}

static void
handle_config(struct selector_key *key, char **cursor)
{
    char *action = next_token(cursor);

    if (g_config == NULL) {
        queue_response(key, "-ERR config unavailable\n");
    } else if (action == NULL) {
        queue_response(key, "-ERR usage CONFIG GET | CONFIG SET <key> <value>\n");
    } else if (strcmp(action, "GET") == 0) {
        char *extra = next_token(cursor);
        if (extra != NULL) {
            queue_response(key, "-ERR usage CONFIG GET\n");
        } else {
            handle_config_get(key);
        }
    } else if (strcmp(action, "SET") == 0) {
        char *key_name = next_token(cursor);
        char *raw_value = next_token(cursor);
        char *extra = next_token(cursor);
        int value;
        if (key_name == NULL || raw_value == NULL || extra != NULL) {
            queue_response(key, "-ERR usage CONFIG SET <key> <value>\n");
        } else if (!parse_nonnegative(raw_value, &value)) {
            queue_response(key, "-ERR invalid value\n");
        } else if (!config_set_key(g_config, key_name, value)) {
            queue_response(key, "-ERR unknown config key\n");
        } else {
            queue_response(key, "+OK config set\n");
        }
    } else {
        queue_response(key, "-ERR unknown CONFIG command\n");
    }
}

static void
handle_line(struct selector_key *key)
{
    struct mng_session *session = key->data;
    char *cursor = session->line;
    char *cmd;

    trim_right(session->line);
    cmd = next_token(&cursor);
    if (cmd == NULL) {
        queue_response(key, "-ERR empty command\n");
    } else if (strcmp(cmd, "AUTH") == 0) {
        handle_auth(key, session, &cursor);
    } else if (strcmp(cmd, "QUIT") == 0) {
        char *extra = next_token(&cursor);
        if (extra != NULL) {
            queue_response(key, "-ERR usage QUIT\n");
        } else {
            session->closing = true;
            queue_response(key, "+OK bye\n");
        }
    } else if (!require_auth(key, session)) {
        return;
    } else if (strcmp(cmd, "STATS") == 0) {
        handle_stats(key);
    } else if (strcmp(cmd, "USERS") == 0) {
        handle_users(key);
    } else if (strcmp(cmd, "USER") == 0) {
        handle_user(key, &cursor);
    } else if (strcmp(cmd, "CONFIG") == 0) {
        handle_config(key, &cursor);
    } else {
        queue_response(key, "-ERR unknown command\n");
    }
}

void
mng_passive_accept(struct selector_key *key)
{
    struct mng_session *session = NULL;
    int client = accept(key->fd, NULL, NULL);

    if (client < 0) {
        return;
    }
    if (selector_fd_set_nio(client) == -1) {
        close(client);
        return;
    }

    session = calloc(1, sizeof(*session));
    if (session == NULL) {
        close(client);
        return;
    }
    session->fd = client;

    if (selector_register(key->s, client, &mng_handler, OP_READ, session)
        != SELECTOR_SUCCESS) {
        free(session);
        close(client);
        return;
    }
    g_active_sessions++;
    if (g_metrics != NULL) {
        metrics_admin_session_open(g_metrics);
    }
}

/* Drains in_buf; stops if a response is queued, resuming from in_pos later. */
static void
mng_process_input(struct selector_key *key)
{
    struct mng_session *session = key->data;

    while (session->in_pos < session->in_len && session->out_len == 0) {
        char c = session->in_buf[session->in_pos++];
        if (c == '\r') {
            continue;
        }
        if (c == '\n') {
            session->line[session->line_len] = '\0';
            session->line_len = 0;
            handle_line(key);
        } else if (session->line_len + 1 >= sizeof(session->line)) {
            session->line_len = 0;
            queue_response(key, "-ERR line too long\n");
        } else {
            session->line[session->line_len++] = c;
        }
    }
    if (session->in_pos >= session->in_len) {
        session->in_pos = 0;
        session->in_len = 0;
    }
}

static void
mng_read(struct selector_key *key)
{
    struct mng_session *session = key->data;

    if (session->in_pos >= session->in_len) {
        ssize_t n = recv(key->fd, session->in_buf, sizeof(session->in_buf), 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                return;
            }
            selector_unregister_fd(key->s, key->fd);
            return;
        }
        if (n == 0) {
            selector_unregister_fd(key->s, key->fd);
            return;
        }
        session->in_len = (size_t)n;
        session->in_pos = 0;
    }

    mng_process_input(key);
}

static void
mng_write(struct selector_key *key)
{
    struct mng_session *session = key->data;

    while (session->out_sent < session->out_len) {
        ssize_t n = send(key->fd, session->out + session->out_sent,
                         session->out_len - session->out_sent, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                return; /* socket buffer full: resume on the next OP_WRITE */
            }
            selector_unregister_fd(key->s, key->fd);
            return;
        }
        if (n == 0) {
            break;
        }
        session->out_sent += (size_t)n;
    }

    if (session->out_sent == session->out_len) {
        session->out_len = 0;
        session->out_sent = 0;
        if (session->closing) {
            selector_unregister_fd(key->s, key->fd);
            return;
        }
        mng_process_input(key);
        if (session->out_len == 0) {
            selector_set_interest_key(key, OP_READ);
        }
    }
}

static void
mng_close(struct selector_key *key)
{
    struct mng_session *session = key->data;

    if (session != NULL) {
        if (session->fd >= 0) {
            close(session->fd);
        }
        free(session);
    }
    if (g_active_sessions > 0) {
        g_active_sessions--;
    }
    if (g_metrics != NULL) {
        metrics_admin_session_close(g_metrics);
    }
}

unsigned
mng_active_sessions(void)
{
    return g_active_sessions;
}

void
mng_pool_destroy(void)
{
}
