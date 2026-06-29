#include <netdb.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "hello.h"
#include "request.h"
#include "buffer.h"
#include "stm.h"
#include "socks5nio.h"
#include "socks5.h"
#include "auth.h"
#include "users.h"
#include "metrics.h"
#include "dns_worker.h"

#define BUFFER_SIZE 4096
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

    char authenticated_user[256];
};

#define ATTACHMENT(key) ((struct socks5 *)(key)->data)

static struct socks5 *socks5_new(int client_fd);
static void socks5_destroy(struct socks5 *s);
static void socksv5_done(struct selector_key *key);
static void socksv5_read(struct selector_key *key);
static void socksv5_write(struct selector_key *key);
static void socksv5_block(struct selector_key *key);
static void socksv5_close(struct selector_key *key);

static struct socks5 *pool;
static unsigned pool_size;
static const unsigned max_pool = 50;
static users_t *g_users = NULL;
static metrics_t *g_metrics = NULL;
static dns_worker_t *g_dns_worker = NULL;

static unsigned unimplemented_read(struct selector_key *key) {
    (void)key;
    return ERROR;
}

static unsigned unimplemented_write(struct selector_key *key) {
    (void)key;
    return ERROR;
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

    size_t available;
    uint8_t *write_ptr = buffer_write_ptr(hello->rb, &available);
    ssize_t received = recv(key->fd, write_ptr, available, 0);
    if (received <= 0) {
        return ERROR;
    }
    buffer_write_adv(hello->rb, received);

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
        return hello->method == SOCKS_HELLO_USERNAME_PASSWORD ? AUTH_READ : DONE;
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

static void auth_read_init(const unsigned state, struct selector_key *key) {
    (void)state;
    struct auth_st *auth = &ATTACHMENT(key)->client.auth;
    auth->rb = &ATTACHMENT(key)->read_buffer;
    auth->wb = &ATTACHMENT(key)->write_buffer;
    auth_parser_init(&auth->parser);
}

static unsigned auth_process(struct auth_st *auth, struct socks5 *session) {
    uint8_t status = 0x01;
    if (g_users == NULL || users_check(g_users, auth->parser.uname, auth->parser.passwd)) {
        status = 0x00;
        strncpy(session->authenticated_user, auth->parser.uname,
                sizeof(session->authenticated_user) - 1);
        session->authenticated_user[sizeof(session->authenticated_user) - 1] = '\0';
    } else {
        if (g_metrics != NULL) {
            metrics_auth_fail(g_metrics);
        }
    }
    if (auth_marshall(auth->wb, status) < 0) {
        return ERROR;
    }
    return AUTH_WRITE;
}

static unsigned auth_read(struct selector_key *key) {
    struct auth_st *auth = &ATTACHMENT(key)->client.auth;
    unsigned next_state = AUTH_READ;

    size_t available;
    uint8_t *write_ptr = buffer_write_ptr(auth->rb, &available);
    ssize_t received = recv(key->fd, write_ptr, available, 0);
    if (received <= 0) {
        return ERROR;
    }
    buffer_write_adv(auth->rb, received);

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
        return DONE;
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
        if (request_marshall(req->wb, req->reply) < 0) {
            return ERROR;
        }
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
            return ERROR;
        }
        return REQUEST_WRITE;
    }
    /* request_done: proceed to DNS resolution or direct connect */
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
            req->reply = SOCKS_REPLY_GENERAL_FAILURE;
            if (request_marshall(req->wb, req->reply) < 0) {
                return ERROR;
            }
            if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
                return ERROR;
            }
            return REQUEST_WRITE;
        }
        return REQUEST_RESOLV;
    }
    return CONNECTING;
}

static unsigned request_resolv_done(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    struct request_st *req = &s->client.request;

    if (s->origin_resolution == NULL) {
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

    size_t available;
    uint8_t *write_ptr = buffer_write_ptr(req->rb, &available);
    ssize_t received = recv(key->fd, write_ptr, available, 0);
    if (received <= 0) {
        return ERROR;
    }
    buffer_write_adv(req->rb, received);

    enum request_state st = request_consume(req->rb, &req->parser, &error);
    if (error) {
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
        .on_write_ready = unimplemented_write,
    },
    {
        .state = REQUEST_WRITE,
        .on_write_ready = request_write,
    },
    {
        .state = COPY,
        .on_read_ready = unimplemented_read,
        .on_write_ready = unimplemented_write,
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
    const int fds[] = {
        ATTACHMENT(key)->client_fd,
        ATTACHMENT(key)->origin_fd,
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

static void
socksv5_read(struct selector_key *key) {
    struct state_machine *stm = &ATTACHMENT(key)->stm;
    const enum socks_v5state st =stm_handler_read(stm, key);

    if(st == ERROR || st == DONE) {
        socksv5_done(key);
    }
}

static void
socksv5_write(struct selector_key *key) {
    struct state_machine *stm = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_write(stm, key);

    if(st == ERROR || st == DONE) {
        socksv5_done(key);
    }
}

static void
socksv5_block(struct selector_key *key) {
    struct state_machine *stm = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_block(stm, key);

    if(st == ERROR || st == DONE) {
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
    return ;
fail:
    if(client != -1) {
        close(client);
    }
    socks5_destroy(state);
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

    return s;
}

