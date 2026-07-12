#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "hello.h"
#include "request.h"
#include "buffer.h"
#include "netutils.h"
#include "stm.h"
#include "socks5nio.h"
#include "socks5.h"
#include "auth.h"
#include "users.h"
#include "metrics.h"
#include "dns_worker.h"
#include "access_log.h"
#include "config.h"

#define BUFFER_SIZE 4096
#define DESTINATION_MAX_LEN (MAX_FQDN_LEN + 1)
#define N(x) (sizeof(x) / sizeof((x)[0]))

enum socks_v5state{
    HELLO_READ=0,
    HELLO_WRITE,
    AUTH_READ,
    AUTH_WRITE,
    REQUEST_READ,
    REQUEST_RESOLV,
    CONNECTING,
    REQUEST_WRITE,
    COPY,
    DONE,
    ERROR,
};

struct hello_st {
    buffer *rb, *wb;
    struct hello_parser parser;
    uint8_t method;
};

struct auth_st {
    buffer *rb, *wb;
    struct auth_parser parser;
    uint8_t status;
};

struct request_st {
    buffer *rb, *wb;
    struct request_parser parser;
    struct socks5_request request;
    uint8_t reply;
};

struct copy {
    int read_fd;
    int write_fd;
    buffer *rb;
    bool eof;
    bool write_closed;
    uint64_t transferred;
};

struct connecting {
    struct addrinfo *current;
    int error;
    uint8_t reply;
};

struct socks5 {
    int client_fd;
    int origin_fd;

    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;

    struct addrinfo *origin_resolution;
    

    buffer read_buffer;
    buffer write_buffer;
    uint8_t raw_read[BUFFER_SIZE];
    uint8_t raw_write[BUFFER_SIZE];

    struct state_machine stm;

    union {
        struct hello_st hello;
        struct auth_st auth;
        struct request_st request;
        struct copy copy;
    } client;

    union {
        struct connecting conn;
        struct copy copy;
    } orig;

    unsigned references;
    struct socks5 *next;

    /* doubly-linked list of live sessions, walked by socksv5_check_timeouts */
    struct socks5 *active_prev;
    struct socks5 *active_next;

    time_t negotiation_deadline; /* 0 = disabled */
    time_t connect_deadline;     /* 0 = disabled, only meaningful in CONNECTING */
    time_t last_activity;        /* bumped on COPY traffic, for idle_timeout */

    char authenticated_user[256];
    char destination[DESTINATION_MAX_LEN];
    uint16_t destination_port;
    bool destination_set;
    bool tunnel_opened;
    bool log_emitted;
    const char *failure_reason;
};

#define ATTACHMENT(key) ((struct socks5 *)(key)->data)

static struct socks5 *socks5_new(int client_fd);
static void socks5_destroy(struct socks5 *s);
static void socksv5_done(struct selector_key *key);
static void socksv5_read(struct selector_key *key);
static void socksv5_write(struct selector_key *key);
static void socksv5_block(struct selector_key *key);
static void socksv5_close(struct selector_key *key);
static const struct fd_handler socks5_handler;

static struct socks5 *pool;
static unsigned pool_size;
static const unsigned max_pool = 50;
static users_t *g_users = NULL;
static metrics_t *g_metrics = NULL;
static unsigned g_active_sessions = 0;
static dns_worker_t *g_dns_worker = NULL;
static access_log_t *g_access_log = NULL;
static config_t *g_config = NULL;
static struct socks5 *g_active_head = NULL;

static const char *
socks5_log_user(struct socks5 *s)
{
    return s->authenticated_user[0] != '\0' ? s->authenticated_user : NULL;
}

static void
socks5_log_event(struct socks5 *s)
{
    if (g_access_log == NULL || s->log_emitted || !s->destination_set) {
        return;
    }

    if (s->tunnel_opened) { /* CLOSE with real byte counts even on a non-clean end */
        access_log_close(g_access_log, socks5_log_user(s), s->destination,
                         s->destination_port, s->client.copy.transferred,
                         s->orig.copy.transferred);
    } else {
        access_log_fail(g_access_log, socks5_log_user(s), s->destination,
                        s->destination_port, s->failure_reason);
    }
    s->log_emitted = true;
}

static void
socks5_log_open(struct socks5 *s)
{
    if (g_access_log == NULL || !s->destination_set || s->tunnel_opened) {
        return;
    }
    access_log_open(g_access_log, socks5_log_user(s), s->destination,
                    s->destination_port);
    s->tunnel_opened = true;
}

static void
socks5_set_failure(struct socks5 *s, const char *reason)
{
    if (s->failure_reason == NULL) {
        s->failure_reason = reason;
    }
}

static bool
socks5_store_destination(struct socks5 *s, const struct socks5_request *request)
{
    const char *stored = NULL;

    if (request->dest_addr.type == SOCKS_ATYP_FQDN) {
        strncpy(s->destination, request->dest_addr.fqdn,
                sizeof(s->destination) - 1);
        s->destination[sizeof(s->destination) - 1] = '\0';
        stored = s->destination;
    } else if (request->dest_addr.type == SOCKS_ATYP_IPV4) {
        stored = inet_ntop(AF_INET, &request->dest_addr.ipv4,
                           s->destination, sizeof(s->destination));
    } else if (request->dest_addr.type == SOCKS_ATYP_IPV6) {
        stored = inet_ntop(AF_INET6, &request->dest_addr.ipv6,
                           s->destination, sizeof(s->destination));
    }

    if (stored == NULL) {
        socks5_set_failure(s, "invalid destination");
        return false;
    }
    s->destination_port = request->dest_port;
    s->destination_set = true;
    return true;
}

static void on_hello_method(struct hello_parser *parser, uint8_t method) {
    uint8_t *selected = parser->data;
    if (method == SOCKS_HELLO_USERNAME_PASSWORD) {
        *selected = method;
    } else if (method == SOCKS_HELLO_NOAUTHENTICATION_REQUIRED
               && *selected == SOCKS_HELLO_NO_ACCEPTABLE_METHODS) {
        *selected = method;
    }
}

static void hello_read_init(const unsigned state, struct selector_key *key) {
    (void)state;
    struct hello_st *hello = &ATTACHMENT(key)->client.hello;
    hello->rb = &ATTACHMENT(key)->read_buffer;
    hello->wb = &ATTACHMENT(key)->write_buffer;
    hello->method = SOCKS_HELLO_NO_ACCEPTABLE_METHODS;
    hello->parser.data = &hello->method;
    hello->parser.on_authentication_method = on_hello_method;
    hello_parser_init(&hello->parser);
}

static unsigned hello_process(struct hello_st *hello) {
    if (hello->method != SOCKS_HELLO_USERNAME_PASSWORD
        && g_users != NULL && users_count(g_users) > 0) {
        hello->method = SOCKS_HELLO_NO_ACCEPTABLE_METHODS;
    }
    if (hello_marshall(hello->wb, hello->method) < 0) {
        return ERROR;
    }
    if (hello->method == SOCKS_HELLO_NO_ACCEPTABLE_METHODS) {
        return ERROR;
    }
    return HELLO_WRITE;
}

static unsigned hello_read(struct selector_key *key) {
    struct hello_st *hello = &ATTACHMENT(key)->client.hello;
    bool error = false;
    unsigned next_state = HELLO_READ;

    if (!buffer_can_read(hello->rb)) {
        size_t available;
        uint8_t *write_ptr = buffer_write_ptr(hello->rb, &available);
        ssize_t received = recv(key->fd, write_ptr, available, 0);
        if (received <= 0) {
            return ERROR;
        }
        buffer_write_adv(hello->rb, received);
    }

    enum hello_state state = hello_consume(hello->rb, &hello->parser, &error);
    if (error) {
        return ERROR;
    }
    if (hello_is_done(state, NULL)) {
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
            return ERROR;
        }
        next_state = hello_process(hello);
    }
    return next_state;
}

static unsigned hello_write(struct selector_key *key) {
    struct hello_st *hello = &ATTACHMENT(key)->client.hello;

    size_t pending;
    uint8_t *read_ptr = buffer_read_ptr(hello->wb, &pending);
    ssize_t sent = send(key->fd, read_ptr, pending, 0);
    if (sent <= 0) {
        return ERROR;
    }
    buffer_read_adv(hello->wb, sent);

    if (!buffer_can_read(hello->wb)) {
        if (selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
            return ERROR;
        }
        return hello->method == SOCKS_HELLO_USERNAME_PASSWORD ? AUTH_READ : REQUEST_READ;
    }
    return HELLO_WRITE;
}

void socksv5_set_users(users_t *u) {
    g_users = u;
}

void socksv5_set_metrics(metrics_t *m) {
    g_metrics = m;
}

void socksv5_set_dns_worker(dns_worker_t *w) {
    g_dns_worker = w;
}

void socksv5_set_access_log(access_log_t *log) {
    g_access_log = log;
}

void socksv5_set_config(config_t *c) {
    g_config = c;
}

static void auth_read_init(const unsigned state, struct selector_key *key) {
    (void)state;
    struct auth_st *auth = &ATTACHMENT(key)->client.auth;
    auth->rb = &ATTACHMENT(key)->read_buffer;
    auth->wb = &ATTACHMENT(key)->write_buffer;
    auth->status = 0x01;
    auth_parser_init(&auth->parser);
}

static unsigned auth_process(struct auth_st *auth, struct socks5 *session) {
    auth->status = 0x01;
    if (g_users == NULL || users_check(g_users, auth->parser.uname, auth->parser.passwd)) {
        auth->status = 0x00;
        strncpy(session->authenticated_user, auth->parser.uname,
                sizeof(session->authenticated_user) - 1);
        session->authenticated_user[sizeof(session->authenticated_user) - 1] = '\0';
    } else {
        if (g_metrics != NULL) {
            metrics_auth_fail(g_metrics);
        }
    }
    if (auth_marshall(auth->wb, auth->status) < 0) {
        return ERROR;
    }
    return AUTH_WRITE;
}

static unsigned auth_read(struct selector_key *key) {
    struct auth_st *auth = &ATTACHMENT(key)->client.auth;
    unsigned next_state = AUTH_READ;

    if (!buffer_can_read(auth->rb)) {
        size_t available;
        uint8_t *write_ptr = buffer_write_ptr(auth->rb, &available);
        ssize_t received = recv(key->fd, write_ptr, available, 0);
        if (received <= 0) {
            return ERROR;
        }
        buffer_write_adv(auth->rb, received);
    }

    bool error = false;
    enum auth_state state = auth_consume(auth->rb, &auth->parser, &error);
    if (error) {
        return ERROR;
    }
    if (auth_is_done(state, NULL)) {
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
            return ERROR;
        }
        next_state = auth_process(auth, ATTACHMENT(key));
    }
    return next_state;
}

static unsigned auth_write(struct selector_key *key) {
    struct auth_st *auth = &ATTACHMENT(key)->client.auth;

    size_t pending;
    uint8_t *read_ptr = buffer_read_ptr(auth->wb, &pending);
    ssize_t sent = send(key->fd, read_ptr, pending, 0);
    if (sent <= 0) {
        return ERROR;
    }
    buffer_read_adv(auth->wb, sent);

    if (!buffer_can_read(auth->wb)) {
        if (selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
            return ERROR;
        }
        return auth->status == 0x00 ? REQUEST_READ : DONE;
    }
    return AUTH_WRITE;
}

static void request_read_init(const unsigned state, struct selector_key *key) {
    (void)state;
    struct request_st *req = &ATTACHMENT(key)->client.request;
    req->rb = &ATTACHMENT(key)->read_buffer;
    req->wb = &ATTACHMENT(key)->write_buffer;
    req->reply = SOCKS_REPLY_GENERAL_FAILURE;
    req->parser.request = &req->request;
    request_parser_init(&req->parser);
}

static unsigned request_process(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    struct request_st *req = &s->client.request;
    enum request_state st = req->parser.state;

    if (st == request_error_unsupported_cmd || st == request_error_unsupported_atyp) {
        req->reply = (st == request_error_unsupported_cmd)
            ? SOCKS_REPLY_CMD_NOT_SUPPORTED
            : SOCKS_REPLY_ATYP_NOT_SUPPORTED;
        socks5_set_failure(s, st == request_error_unsupported_cmd
                           ? "unsupported command"
                           : "unsupported address type");
        if (request_marshall(req->wb, req->reply) < 0) {
            return ERROR;
        }
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
            return ERROR;
        }
        return REQUEST_WRITE;
    }
    /* request_done: proceed to DNS resolution or direct connect */
    if (!socks5_store_destination(s, &req->request)) {
        return ERROR;
    }
    if (selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS) {
        return ERROR;
    }
    if (req->request.dest_addr.type == SOCKS_ATYP_FQDN) {
        if (g_dns_worker == NULL ||
            dns_worker_submit(g_dns_worker, key->fd,
                              req->request.dest_addr.fqdn,
                              req->request.dest_port,
                              &s->origin_resolution,
                              key->s) != 0) {
            socks5_set_failure(s, "dns submit failed");
            req->reply = SOCKS_REPLY_GENERAL_FAILURE;
            if (request_marshall(req->wb, req->reply) < 0) {
                return ERROR;
            }
            if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
                return ERROR;
            }
            return REQUEST_WRITE;
        }
        s->references++; /* the DNS worker holds a pointer into this session */
        return REQUEST_RESOLV;
    }
    return CONNECTING;
}

static unsigned request_resolv_done(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    struct request_st *req = &s->client.request;

    s->references--; /* release the DNS worker's reference */

    if (s->origin_resolution == NULL) {
        socks5_set_failure(s, "dns resolution failed");
        req->reply = SOCKS_REPLY_HOST_UNREACHABLE;
        if (request_marshall(req->wb, req->reply) < 0) {
            return ERROR;
        }
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
            return ERROR;
        }
        return REQUEST_WRITE;
    }
    s->orig.conn.current = s->origin_resolution;
    return CONNECTING;
}

static unsigned request_read(struct selector_key *key) {
    struct request_st *req = &ATTACHMENT(key)->client.request;
    bool error = false;

    if (!buffer_can_read(req->rb)) {
        size_t available;
        uint8_t *write_ptr = buffer_write_ptr(req->rb, &available);
        ssize_t received = recv(key->fd, write_ptr, available, 0);
        if (received <= 0) {
            return ERROR;
        }
        buffer_write_adv(req->rb, received);
    }

    enum request_state st = request_consume(req->rb, &req->parser, &error);
    if (error) {
        socks5_set_failure(ATTACHMENT(key), "invalid request");
        return ERROR;
    }

    if (request_is_done(st, NULL)) {
        return request_process(key);
    }
    return REQUEST_READ;
}

static unsigned request_write(struct selector_key *key) {
    struct request_st *req = &ATTACHMENT(key)->client.request;

    size_t pending;
    uint8_t *read_ptr = buffer_read_ptr(req->wb, &pending);
    ssize_t sent = send(key->fd, read_ptr, pending, 0);
    if (sent <= 0) {
        return ERROR;
    }
    buffer_read_adv(req->wb, sent);

    if (!buffer_can_read(req->wb)) {
        if (req->reply == SOCKS_REPLY_SUCCEEDED) {
            if (selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
                return ERROR;
            }
            return COPY;
        }
        return DONE;
    }
    return REQUEST_WRITE;
}

/*
 * Tries to create a non-blocking socket and connect to addr.
 * Stores the new fd in s->origin_fd on success.
 * Returns 0 if connect() succeeded or returned EINPROGRESS, -1 otherwise.
 */
static int
connecting_try_one(struct socks5 *s, const struct sockaddr *addr, socklen_t addrlen)
{
    int fd = socket(addr->sa_family, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    if (selector_fd_set_nio(fd) < 0) {
        close(fd);
        return -1;
    }
    if (connect(fd, addr, addrlen) < 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    s->origin_fd = fd;
    return 0;
}

/*
 * Iterates s->orig.conn.current (addrinfo list from DNS).
 * On the first address that accepts a connect(), registers origin_fd with
 * OP_WRITE and increments s->references.
 * If all addresses are exhausted, sets client_fd to OP_WRITE so
 * connecting_write can send the error reply.
 */
static void
connecting_try_addrinfo(struct selector_key *key)
{
    struct socks5 *s = ATTACHMENT(key);

    while (s->orig.conn.current != NULL) {
        struct addrinfo *ai = s->orig.conn.current;
        s->orig.conn.current = ai->ai_next;

        if (connecting_try_one(s, ai->ai_addr, ai->ai_addrlen) == 0) {
            s->references++;
            selector_register(key->s, s->origin_fd, &socks5_handler, OP_WRITE, s);
            return;
        }
        s->orig.conn.reply = errno_to_socks_reply(errno);
    }
    socks5_set_failure(s, "connect failed");
    selector_set_interest(key->s, s->client_fd, OP_WRITE);
}

static void
connecting_init(const unsigned state, struct selector_key *key)
{
    (void)state;
    struct socks5 *s = ATTACHMENT(key);
    struct request_st *req = &s->client.request;
    s->orig.conn.reply = SOCKS_REPLY_GENERAL_FAILURE;
    s->connect_deadline = (g_config != NULL && g_config->connect_timeout > 0)
        ? time(NULL) + g_config->connect_timeout : 0;

    if (s->orig.conn.current != NULL) {
        /* FQDN */
        connecting_try_addrinfo(key);
    } else {
        /* IPv4/IPv6 */
        struct sockaddr_storage ss;
        socklen_t sslen;
        memset(&ss, 0, sizeof(ss));

        if (req->request.dest_addr.type == SOCKS_ATYP_IPV4) {
            struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
            sin->sin_family = AF_INET;
            sin->sin_addr = req->request.dest_addr.ipv4;
            sin->sin_port = htons(req->request.dest_port);
            sslen = sizeof(*sin);
        } else {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
            sin6->sin6_family = AF_INET6;
            sin6->sin6_addr = req->request.dest_addr.ipv6;
            sin6->sin6_port = htons(req->request.dest_port);
            sslen = sizeof(*sin6);
        }

        if (connecting_try_one(s, (struct sockaddr *)&ss, sslen) == 0) {
            s->references++;
            selector_register(key->s, s->origin_fd, &socks5_handler, OP_WRITE, s);
        } else {
            s->orig.conn.reply = errno_to_socks_reply(errno);
            socks5_set_failure(s, "connect failed");
            selector_set_interest(key->s, s->client_fd, OP_WRITE);
        }
    }
}

static unsigned
connecting_write(struct selector_key *key)
{
    struct socks5 *s = ATTACHMENT(key);
    struct request_st *req = &s->client.request;

    if (key->fd == s->client_fd) {
        /* Connect failed */
        socks5_set_failure(s, "connect failed");
        req->reply = s->orig.conn.reply;
        if (g_metrics != NULL) {
            metrics_origin_fail(g_metrics);
        }
        if (request_marshall(req->wb, req->reply) < 0) {
            return ERROR;
        }
        return REQUEST_WRITE;
    }

    int err = 0;
    socklen_t len = sizeof(err);
    if (getsockopt(key->fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0) {
        err = errno;
    }

    if (err == 0) {
        /* Connect succeeded */
        if (g_metrics != NULL) {
            metrics_origin_ok(g_metrics);
        }
        req->reply = SOCKS_REPLY_SUCCEEDED;
        if (request_marshall(req->wb, req->reply) < 0) {
            return ERROR;
        }
        if (selector_set_interest(key->s, s->client_fd, OP_WRITE) != SELECTOR_SUCCESS) {
            return ERROR;
        }
        if (selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS) {
            return ERROR;
        }
        return REQUEST_WRITE;
    }

    /* Connect failed on this address */
    s->orig.conn.reply = errno_to_socks_reply(err);
    selector_unregister_fd(key->s, s->origin_fd);
    close(s->origin_fd);
    s->origin_fd = -1;

    if (s->orig.conn.current != NULL) {
        /* More addresses to try (FQDN with multiple IPs) */
        connecting_try_addrinfo(key);
        return CONNECTING;
    }

    /* No more addresses */
    socks5_set_failure(s, "connect failed");
    if (g_metrics != NULL) {
        metrics_origin_fail(g_metrics);
    }
    req->reply = s->orig.conn.reply;
    if (request_marshall(req->wb, req->reply) < 0) {
        return ERROR;
    }
    if (selector_set_interest(key->s, s->client_fd, OP_WRITE) != SELECTOR_SUCCESS) {
        return ERROR;
    }
    return REQUEST_WRITE;
}

/* Called on a -c timeout: drop origin_fd and wake client_fd for OP_WRITE,
 * reusing connecting_write's key->fd == client_fd branch to send the reply. */
static void
connecting_timeout(struct socks5 *s, fd_selector selector)
{
    if (s->origin_fd != -1) {
        selector_unregister_fd(selector, s->origin_fd);
        close(s->origin_fd);
        s->origin_fd = -1;
    }
    s->orig.conn.current = NULL;
    s->orig.conn.reply = SOCKS_REPLY_TTL_EXPIRED;
    selector_set_interest(selector, s->client_fd, OP_WRITE);
}

static bool
copy_is_done(struct socks5 *s)
{
    return s->client.copy.write_closed && s->orig.copy.write_closed;
}

static int
copy_shutdown_write(struct copy *copy)
{
    if (copy->eof && !buffer_can_read(copy->rb) && !copy->write_closed) {
        if (shutdown(copy->write_fd, SHUT_WR) < 0
            && errno != ENOTCONN && errno != EPIPE) {
            return -1;
        }
        copy->write_closed = true;
    }
    return 0;
}

static fd_interest
copy_client_interest(struct socks5 *s)
{
    fd_interest interest = OP_NOOP;

    if (!s->client.copy.eof && buffer_can_write(s->client.copy.rb)) {
        interest |= OP_READ;
    }
    if (!s->orig.copy.write_closed && buffer_can_read(s->orig.copy.rb)) {
        interest |= OP_WRITE;
    }
    return interest;
}

static fd_interest
copy_origin_interest(struct socks5 *s)
{
    fd_interest interest = OP_NOOP;

    if (!s->orig.copy.eof && buffer_can_write(s->orig.copy.rb)) {
        interest |= OP_READ;
    }
    if (!s->client.copy.write_closed && buffer_can_read(s->client.copy.rb)) {
        interest |= OP_WRITE;
    }
    return interest;
}

static int
copy_update_interests(struct selector_key *key)
{
    struct socks5 *s = ATTACHMENT(key);

    if (selector_set_interest(key->s, s->client_fd,
                              copy_client_interest(s)) != SELECTOR_SUCCESS) {
        return -1;
    }
    if (selector_set_interest(key->s, s->origin_fd,
                              copy_origin_interest(s)) != SELECTOR_SUCCESS) {
        return -1;
    }
    return 0;
}

static struct copy *
copy_read_state(struct socks5 *s, int fd)
{
    if (fd == s->client_fd) {
        return &s->client.copy;
    }
    if (fd == s->origin_fd) {
        return &s->orig.copy;
    }
    return NULL;
}

static struct copy *
copy_write_state(struct socks5 *s, int fd)
{
    if (fd == s->client_fd) {
        return &s->orig.copy;
    }
    if (fd == s->origin_fd) {
        return &s->client.copy;
    }
    return NULL;
}

static void
copy_init(const unsigned state, struct selector_key *key)
{
    (void)state;
    struct socks5 *s = ATTACHMENT(key);

    s->client.copy.read_fd = s->client_fd;
    s->client.copy.write_fd = s->origin_fd;
    s->client.copy.rb = &s->read_buffer;
    s->client.copy.eof = false;
    s->client.copy.write_closed = false;
    s->client.copy.transferred = 0;

    s->orig.copy.read_fd = s->origin_fd;
    s->orig.copy.write_fd = s->client_fd;
    s->orig.copy.rb = &s->write_buffer;
    s->orig.copy.eof = false;
    s->orig.copy.write_closed = false;
    s->orig.copy.transferred = 0;

    socks5_log_open(s);
    copy_update_interests(key);
}

static unsigned
copy_read(struct selector_key *key)
{
    struct socks5 *s = ATTACHMENT(key);
    struct copy *copy = copy_read_state(s, key->fd);
    if (copy == NULL) {
        return ERROR;
    }

    if (!buffer_can_write(copy->rb)) {
        buffer_compact(copy->rb);
    }
    if (!buffer_can_write(copy->rb)) {
        return copy_update_interests(key) == 0 ? COPY : ERROR;
    }

    size_t available;
    uint8_t *write_ptr = buffer_write_ptr(copy->rb, &available);
    ssize_t received = recv(copy->read_fd, write_ptr, available, 0);
    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            return copy_update_interests(key) == 0 ? COPY : ERROR;
        }
        return ERROR;
    }
    if (received == 0) {
        copy->eof = true;
    } else {
        buffer_write_adv(copy->rb, received);
        s->last_activity = time(NULL);
    }

    if (copy_shutdown_write(copy) < 0) {
        return ERROR;
    }
    if (copy_is_done(s)) {
        return DONE;
    }
    return copy_update_interests(key) == 0 ? COPY : ERROR;
}

static unsigned
copy_write(struct selector_key *key)
{
    struct socks5 *s = ATTACHMENT(key);
    struct copy *copy = copy_write_state(s, key->fd);
    if (copy == NULL) {
        return ERROR;
    }

    if (!buffer_can_read(copy->rb)) {
        if (copy_shutdown_write(copy) < 0) {
            return ERROR;
        }
        if (copy_is_done(s)) {
            return DONE;
        }
        return copy_update_interests(key) == 0 ? COPY : ERROR;
    }

    size_t pending;
    uint8_t *read_ptr = buffer_read_ptr(copy->rb, &pending);
    ssize_t sent = send(copy->write_fd, read_ptr, pending, 0);
    if (sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            return copy_update_interests(key) == 0 ? COPY : ERROR;
        }
        return ERROR;
    }
    if (sent == 0) {
        return copy_update_interests(key) == 0 ? COPY : ERROR;
    }

    buffer_read_adv(copy->rb, sent);
    copy->transferred += (uint64_t)sent;
    if (copy == &s->client.copy) {
        if (g_metrics != NULL) {
            metrics_add_bytes_c2o(g_metrics, (uint64_t)sent);
        }
    } else if (g_metrics != NULL) {
        metrics_add_bytes_o2c(g_metrics, (uint64_t)sent);
    }

    if (copy_shutdown_write(copy) < 0) {
        return ERROR;
    }
    if (copy_is_done(s)) {
        return DONE;
    }
    return copy_update_interests(key) == 0 ? COPY : ERROR;
}

static const struct state_definition client_statbl[] = {
    {
        .state = HELLO_READ,
        .on_arrival = hello_read_init,
        .on_read_ready = hello_read,
    },
    {
        .state = HELLO_WRITE,
        .on_write_ready = hello_write,
    },
    {
        .state = AUTH_READ,
        .on_arrival = auth_read_init,
        .on_read_ready = auth_read,
    },
    {
        .state = AUTH_WRITE,
        .on_write_ready = auth_write,
    },
    {
        .state = REQUEST_READ,
        .on_arrival = request_read_init,
        .on_read_ready = request_read,
    },
    {
        .state = REQUEST_RESOLV,
        .on_block_ready = request_resolv_done,
    },
    {
        .state = CONNECTING,
        .on_arrival = connecting_init,
        .on_write_ready = connecting_write,
    },
    {
        .state = REQUEST_WRITE,
        .on_write_ready = request_write,
    },
    {
        .state = COPY,
        .on_arrival = copy_init,
        .on_read_ready = copy_read,
        .on_write_ready = copy_write,
    },
    {
        .state = DONE,
    },
    {
        .state = ERROR,
    },
};

static void
socks5_destroy_(struct socks5* s) {
    if(s->origin_resolution != NULL) {
        freeaddrinfo(s->origin_resolution);
        s->origin_resolution = 0;
    }
    free(s);
}

static void
socks5_destroy(struct socks5 *s) {
    if(s == NULL) {
        // nada para hacer
    } else if(s->references == 1) {
        if(s != NULL) {
            if(pool_size < max_pool) {
                if(s->origin_resolution!=NULL){
                    freeaddrinfo(s->origin_resolution);
                    s->origin_resolution=NULL;
                }
                s->next = pool;
                pool    = s;
                pool_size++;
            } else {
                socks5_destroy_(s);
            }
        }
    } else {
        s->references -= 1;
    }
}

void
socksv5_pool_destroy(void) {
    struct socks5 *next, *s;
    for(s = pool; s != NULL ; s = next) {
        next = s->next;
        free(s);
    }
    pool= NULL;
    pool_size =0;
}

static void
socksv5_done(struct selector_key* key) {
    struct socks5 *s = ATTACHMENT(key);
    socks5_log_event(s);

    if (s->active_prev != NULL) {
        s->active_prev->active_next = s->active_next;
    } else {
        g_active_head = s->active_next;
    }
    if (s->active_next != NULL) {
        s->active_next->active_prev = s->active_prev;
    }
    s->active_prev = NULL;
    s->active_next = NULL;

    if (g_active_sessions > 0) {
        g_active_sessions--;
    }
    if (g_metrics != NULL) {
        metrics_conn_closed(g_metrics);
    }

    const int fds[] = {
        s->client_fd,
        s->origin_fd,
    };
    for(unsigned i = 0; i < N(fds); i++) {
        if(fds[i] != -1) {
            if(SELECTOR_SUCCESS != selector_unregister_fd(key->s, fds[i])) {
                abort();
            }
            close(fds[i]);
        }
    }
}

/* Processes any already-buffered bytes left over from a coalesced recv(). */
static enum socks_v5state
socksv5_drain_pending(struct selector_key *key, enum socks_v5state st) {
    struct socks5 *s = ATTACHMENT(key);
    struct state_machine *stm = &s->stm;

    while ((st == HELLO_READ || st == AUTH_READ || st == REQUEST_READ)
           && buffer_can_read(&s->read_buffer)) {
        st = stm_handler_read(stm, key);
    }
    return st;
}

static void
socksv5_read(struct selector_key *key) {
    struct state_machine *stm = &ATTACHMENT(key)->stm;
    enum socks_v5state st = stm_handler_read(stm, key);
    st = socksv5_drain_pending(key, st);

    if(st == ERROR || st == DONE) {
        if (st == ERROR) {
            socks5_set_failure(ATTACHMENT(key), "read error");
        }
        socksv5_done(key);
    }
}

static void
socksv5_write(struct selector_key *key) {
    struct state_machine *stm = &ATTACHMENT(key)->stm;
    enum socks_v5state st = stm_handler_write(stm, key);
    st = socksv5_drain_pending(key, st);

    if(st == ERROR || st == DONE) {
        if (st == ERROR) {
            socks5_set_failure(ATTACHMENT(key), "write error");
        }
        socksv5_done(key);
    }
}

static void
socksv5_block(struct selector_key *key) {
    struct state_machine *stm = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_block(stm, key);

    if(st == ERROR || st == DONE) {
        if (st == ERROR) {
            socks5_set_failure(ATTACHMENT(key), "block error");
        }
        socksv5_done(key);
    }
}

static void
socksv5_close(struct selector_key *key) {
    struct socks5 * s=ATTACHMENT(key);
    socks5_destroy(s);
}

static const struct fd_handler socks5_handler = {
    .handle_read   = socksv5_read,
    .handle_write  = socksv5_write,
    .handle_close  = socksv5_close,
    .handle_block  = socksv5_block,
};

void
socksv5_passive_accept(struct selector_key *key) {
    struct sockaddr_storage       client_addr;
    socklen_t                     client_addr_len = sizeof(client_addr);
    struct socks5                *state           = NULL;

    const int client = accept(key->fd, (struct sockaddr*) &client_addr,
                                                          &client_addr_len);
    if(client == -1) {
        goto fail;
    }
    if(selector_fd_set_nio(client) == -1) {
        goto fail;
    }
    if (g_config != NULL && g_config->max_connections > 0
        && g_active_sessions >= (unsigned)g_config->max_connections) {
        close(client);
        if (g_metrics != NULL) {
            metrics_conn_rejected(g_metrics);
        }
        return;
    }
    state = socks5_new(client);
    if(state == NULL) {
        // sin un estado, nos es imposible manejaro.
        // tal vez deberiamos apagar accept() hasta que detectemos
        // que se liberó alguna conexión.
        goto fail;
    }
    memcpy(&state->client_addr, &client_addr, client_addr_len);
    state->client_addr_len = client_addr_len;

    if(SELECTOR_SUCCESS != selector_register(key->s, client, &socks5_handler,
                                              OP_READ, state)) {
        goto fail;
    }
    g_active_sessions++;
    if (g_metrics != NULL) {
        metrics_conn_accepted(g_metrics);
    }
    return ;
fail:
    if(client != -1) {
        close(client);
    }
    if (g_metrics != NULL) {
        metrics_conn_rejected(g_metrics);
    }
    socks5_destroy(state);
}

unsigned
socksv5_active_sessions(void)
{
    return g_active_sessions;
}

/* Periodic sweep enforcing -t/-c/-i over every active session. */
void
socksv5_check_timeouts(fd_selector selector)
{
    const time_t now = time(NULL);
    struct socks5 *s = g_active_head;

    while (s != NULL) {
        struct socks5 *next = s->active_next;
        const enum socks_v5state st = (enum socks_v5state)stm_state(&s->stm);

        if (st == CONNECTING) {
            if (s->connect_deadline != 0 && now >= s->connect_deadline) {
                connecting_timeout(s, selector);
            }
        } else if (st == COPY) {
            if (g_config != NULL && g_config->idle_timeout > 0
                && now - s->last_activity >= g_config->idle_timeout) {
                socks5_set_failure(s, "idle timeout");
                struct selector_key key = { .s = selector, .fd = s->client_fd, .data = s };
                socksv5_done(&key);
            }
        } else if (st != DONE && st != ERROR && st != REQUEST_RESOLV) {
            /* skip REQUEST_RESOLV: the DNS worker may still hold a pointer tied to client_fd */
            if (s->negotiation_deadline != 0 && now >= s->negotiation_deadline) {
                socks5_set_failure(s, "negotiation timeout");
                struct selector_key key = { .s = selector, .fd = s->client_fd, .data = s };
                socksv5_done(&key);
            }
        }

        s = next;
    }
}

static struct socks5*
socks5_new(int client_fd) {
    struct socks5 *s;
    if(pool!=NULL){
        s=pool;
        pool=pool->next;
        pool_size--;
    }else{
        s=malloc(sizeof(struct socks5));
        if(s==NULL){
            return NULL;
        }
    }
    memset(s, 0, sizeof(*s));
    s->client_fd=client_fd;
    s->origin_fd=-1;
    s->origin_resolution=NULL;
    s->references=1;
    s->next=NULL;

    s->stm.initial=HELLO_READ;
    s->stm.states=client_statbl;
    s->stm.max_state=ERROR;
    stm_init(&s->stm);


    buffer_init(&s->read_buffer, BUFFER_SIZE, s->raw_read);
    buffer_init(&s->write_buffer, BUFFER_SIZE, s->raw_write);

    const time_t now = time(NULL);
    s->last_activity = now;
    s->negotiation_deadline = (g_config != NULL && g_config->negotiation_timeout > 0)
        ? now + g_config->negotiation_timeout : 0;
    s->connect_deadline = 0;

    s->active_prev = NULL;
    s->active_next = g_active_head;
    if (g_active_head != NULL) {
        g_active_head->active_prev = s;
    }
    g_active_head = s;

    return s;
}
