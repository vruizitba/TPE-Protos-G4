/**
 * socks5.c - controla el flujo de un proxy SOCKSv5 (sockets no bloqueantes)
 *
 * Referencia de la cátedra. El bloque #if 0 contiene el esqueleto original;
 * los `...' del ejemplo están marcados como TODO.
 * Las funciones compilables viven debajo del bloque.
 */

/* ============================================================
 * REFERENCIA — implementar
 * ============================================================ */
#if 0

#include<stdio.h>
#include <stdlib.h>  // malloc
#include <string.h>  // memset
#include <assert.h>  // assert
#include <errno.h>
#include <time.h>
#include <unistd.h>  // close
#include <pthread.h>

#include <arpa/inet.h>

#include "hello.h"
#include "request.h"
#include "buffer.h"

#include "stm.h"
#include "socks5nio.h"
#include"netutils.h"

#define N(x) (sizeof(x)/sizeof((x)[0]))


/** maquina de estados general */
enum socks_v5state {
    /**
     * recibe el mensaje `hello` del cliente, y lo procesa
     *
     * Intereses:
     *     - OP_READ sobre client_fd
     *
     * Transiciones:
     *   - HELLO_READ  mientras el mensaje no esté completo
     *   - HELLO_WRITE cuando está completo
     *   - ERROR       ante cualquier error (IO/parseo)
     */
    HELLO_READ,

    /**
     * envía la respuesta del `hello' al cliente.
     *
     * Intereses:
     *     - OP_WRITE sobre client_fd
     *
     * Transiciones:
     *   - HELLO_WRITE  mientras queden bytes por enviar
     *   - REQUEST_READ cuando se enviaron todos los bytes
     *   - ERROR        ante cualquier error (IO/parseo)
     */
    HELLO_WRITE,

    /* TODO: AUTH_READ, AUTH_WRITE, REQUEST_READ, REQUEST_WRITE,
             REQUEST_RESOLV, CONNECTING, COPY */

    // estados terminales
    DONE,
    ERROR,
};

////////////////////////////////////////////////////////////////////
// Definición de variables para cada estado

/** usado por HELLO_READ, HELLO_WRITE */
struct hello_st {
    /** buffer utilizado para I/O */
    buffer               *rb, *wb;
    struct hello_parser   parser;
    /** el método de autenticación seleccionado */
    uint8_t               method;
} ;

/* TODO: struct request_st, struct connecting, struct copy */

/*
 * Si bien cada estado tiene su propio struct que le da un alcance
 * acotado, disponemos de la siguiente estructura para hacer una única
 * alocación cuando recibimos la conexión.
 *
 * Se utiliza un contador de referencias (references) para saber cuando debemos
 * liberarlo finalmente, y un pool para reusar alocaciones previas.
 */
struct socks5 {
    /* TODO: client_fd, origin_fd, client_addr, origin_resolution,
             read_buffer, write_buffer, references, next, pool */

    /** maquinas de estados */
    struct state_machine          stm;

    /** estados para el client_fd */
    union {
        struct hello_st           hello;
        struct request_st         request;
        struct copy               copy;
    } client;
    /** estados para el origin_fd */
    union {
        struct connecting         conn;
        struct copy               copy;
    } orig;

    /* TODO: resto de campos (user, dest, metrics, access_log, etc.) */
};


/** realmente destruye */
static void
socks5_destroy_(struct socks5* s) {
    if(s->origin_resolution != NULL) {
        freeaddrinfo(s->origin_resolution);
        s->origin_resolution = 0;
    }
    free(s);
}

/**
 * destruye un  `struct socks5', tiene en cuenta las referencias
 * y el pool de objetos.
 */
static void
socks5_destroy(struct socks5 *s) {
    if(s == NULL) {
        // nada para hacer
    } else if(s->references == 1) {
        if(s != NULL) {
            if(pool_size < max_pool) {
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
}

/** obtiene el struct (socks5 *) desde la llave de selección  */
#define ATTACHMENT(key) ( (struct socks5 *)(key)->data)

/* declaración forward de los handlers de selección de una conexión
 * establecida entre un cliente y el proxy.
 */
static void socksv5_read   (struct selector_key *key);
static void socksv5_write  (struct selector_key *key);
static void socksv5_block  (struct selector_key *key);
static void socksv5_close  (struct selector_key *key);
static const struct fd_handler socks5_handler = {
    .handle_read   = socksv5_read,
    .handle_write  = socksv5_write,
    .handle_close  = socksv5_close,
    .handle_block  = socksv5_block,
};

/** Intenta aceptar la nueva conexión entrante*/
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

////////////////////////////////////////////////////////////////////////////////
// HELLO
////////////////////////////////////////////////////////////////////////////////

/** callback del parser utilizado en `read_hello' */
static void
on_hello_method(struct hello_parser *p, const uint8_t method) {
    uint8_t *selected  = p->data;

    if(SOCKS_HELLO_NOAUTHENTICATION_REQUIRED == method) {
       *selected = method;
    }
}

/** inicializa las variables de los estados HELLO_… */
static void
hello_read_init(const unsigned state, struct selector_key *key) {
    struct hello_st *d = &ATTACHMENT(key)->client.hello;

    d->rb                              = &(ATTACHMENT(key)->read_buffer);
    d->wb                              = &(ATTACHMENT(key)->write_buffer);
    d->parser.data                     = &d->method;
    d->parser.on_authentication_method = on_hello_method, hello_parser_init(
            &d->parser);
}

static unsigned
hello_process(const struct hello_st* d);

/** lee todos los bytes del mensaje de tipo `hello' y inicia su proceso */
static unsigned
hello_read(struct selector_key *key) {
    struct hello_st *d = &ATTACHMENT(key)->client.hello;
    unsigned  ret      = HELLO_READ;
        bool  error    = false;
     uint8_t *ptr;
      size_t  count;
     ssize_t  n;

    ptr = buffer_write_ptr(d->rb, &count);
    n = recv(key->fd, ptr, count, 0);
    if(n > 0) {
        buffer_write_adv(d->rb, n);
        const enum hello_state st = hello_consume(d->rb, &d->parser, &error);
        if(hello_is_done(st, 0)) {
            if(SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE)) {
                ret = hello_process(d);
            } else {
                ret = ERROR;
            }
        }
    } else {
        ret = ERROR;
    }

    return error ? ERROR : ret;
}

/** procesamiento del mensaje `hello' */
static unsigned
hello_process(const struct hello_st* d) {
    unsigned ret = HELLO_WRITE;

    uint8_t m = d->method;
    const uint8_t r = (m == SOCKS_HELLO_NO_ACCEPTABLE_METHODS) ? 0xFF : 0x00;
    if (-1 == hello_marshall(d->wb, r)) {
        ret  = ERROR;
    }
    if (SOCKS_HELLO_NO_ACCEPTABLE_METHODS == m) {
        ret  = ERROR;
    }
    return ret;
}

/** definición de handlers para cada estado */
static const struct state_definition client_statbl[] = {
    {
        .state            = HELLO_READ,
        .on_arrival       = hello_read_init,
        .on_departure     = hello_read_close,
        .on_read_ready    = hello_read,
    },
    /* TODO: resto de estados */
};

///////////////////////////////////////////////////////////////////////////////
// Handlers top level de la conexión pasiva.
// son los que emiten los eventos a la maquina de estados.
static void
socksv5_done(struct selector_key* key);

static void
socksv5_read(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_read(stm, key);

    if(ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void
socksv5_write(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_write(stm, key);

    if(ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void
socksv5_block(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_block(stm, key);

    if(ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void
socksv5_close(struct selector_key *key) {
    socks5_destroy(ATTACHMENT(key));
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

#endif /* referencia cátedra */

/* ============================================================
 * Implementación
 * ============================================================ */
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "socks5nio.h"
#include "socks5.h"
#include "hello.h"
#include "buffer.h"
#include "stm.h"
#include "auth.h"
#include "users.h"
#include "metrics.h"

#define BUFFER_SIZE 4096

/* TODO: expand with remaining states (request, copy, connecting, pool) */
struct hello_st {
    buffer *read_buffer;
    buffer *write_buffer;
    struct hello_parser parser;
    uint8_t method;
};

struct auth_st {
    buffer *read_buffer;
    buffer *write_buffer;
    struct auth_parser parser;
};

/* DUMMY: provided by the lifecycle module. Only the fields the HELLO states
   need live here.
   TODO: replace with the full session struct. */
struct socks5 {
    int client_fd;
    int origin_fd;

    buffer read_buffer;
    buffer write_buffer;
    uint8_t raw_read[BUFFER_SIZE];
    uint8_t raw_write[BUFFER_SIZE];

    struct state_machine stm;

    union {
        struct hello_st hello;
        struct auth_st auth;
    } client;

    char authenticated_user[256];
};

#define ATTACHMENT(key) ((struct socks5 *)(key)->data)

/* DUMMY: the real enum is defined by the lifecycle module */
enum socks_v5state {
    HELLO_READ,
    HELLO_WRITE,
    AUTH_READ,
    AUTH_WRITE,
    /* TODO: REQUEST_READ, REQUEST_WRITE, REQUEST_RESOLV,
             REQUEST_CONNECTING, COPY */
    DONE,
    ERROR,
};

/* HELLO */

/* Selects the best auth method offered by the client.
   Prefers USERNAME_PASSWORD over NOAUTH. */
static void on_hello_method(struct hello_parser *p, uint8_t method) {
    uint8_t *selected = p->data;
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
    hello->read_buffer = &ATTACHMENT(key)->read_buffer;
    hello->write_buffer = &ATTACHMENT(key)->write_buffer;
    hello->method = SOCKS_HELLO_NO_ACCEPTABLE_METHODS;
    hello->parser.data = &hello->method;
    hello->parser.on_authentication_method = on_hello_method;
    hello_parser_init(&hello->parser);
}

static unsigned hello_process(struct hello_st *hello) {
    if (hello_marshall(hello->write_buffer, hello->method) < 0) {
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
    uint8_t *write_ptr = buffer_write_ptr(hello->read_buffer, &available);
    ssize_t received = recv(key->fd, write_ptr, available, 0);
    if (received <= 0) {
        return ERROR;
    }
    buffer_write_adv(hello->read_buffer, received);

    enum hello_state state = hello_consume(hello->read_buffer, &hello->parser, &error);
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
    uint8_t *read_ptr = buffer_read_ptr(hello->write_buffer, &pending);
    ssize_t sent = send(key->fd, read_ptr, pending, 0);
    if (sent <= 0) {
        return ERROR;
    }
    buffer_read_adv(hello->write_buffer, sent);

    if (!buffer_can_read(hello->write_buffer)) {
        if (selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
            return ERROR;
        }
        return hello->method == SOCKS_HELLO_USERNAME_PASSWORD ? AUTH_READ : DONE;
    }
    return HELLO_WRITE;
}

/* AUTH */

static users_t *g_users = NULL;
static metrics_t *g_metrics = NULL;

/* TODO: call socksv5_set_users() from main after loading users from args */
void socksv5_set_users(users_t *u) {
    g_users = u;
}

/* TODO: call socksv5_set_metrics() from main after creating metrics */
void socksv5_set_metrics(metrics_t *m) {
    g_metrics = m;
}

static void auth_read_init(const unsigned state, struct selector_key *key) {
    (void)state;
    struct auth_st *auth = &ATTACHMENT(key)->client.auth;
    auth->read_buffer = &ATTACHMENT(key)->read_buffer;
    auth->write_buffer = &ATTACHMENT(key)->write_buffer;
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
    if (auth_marshall(auth->write_buffer, status) < 0) {
        return ERROR;
    }
    return AUTH_WRITE;
}

static unsigned auth_read(struct selector_key *key) {
    struct auth_st *auth = &ATTACHMENT(key)->client.auth;
    unsigned next_state = AUTH_READ;

    size_t available;
    uint8_t *write_ptr = buffer_write_ptr(auth->read_buffer, &available);
    ssize_t received = recv(key->fd, write_ptr, available, 0);
    if (received <= 0) {
        return ERROR;
    }
    buffer_write_adv(auth->read_buffer, received);

    bool error = false;
    enum auth_state state = auth_consume(auth->read_buffer, &auth->parser, &error);
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
    uint8_t *read_ptr = buffer_read_ptr(auth->write_buffer, &pending);
    ssize_t sent = send(key->fd, read_ptr, pending, 0);
    if (sent <= 0) {
        return ERROR;
    }
    buffer_read_adv(auth->write_buffer, sent);

    if (!buffer_can_read(auth->write_buffer)) {
        if (selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
            return ERROR;
        }
        /* TODO: on success go to REQUEST_READ; for now DONE */
        return DONE;
    }
    return AUTH_WRITE;
}

/* State table */

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
        .state = DONE,
    },
    {
        .state = ERROR,
    },
};

/* DUMMY: stubs so the binary links. Owned by the lifecycle module.
   TODO: implement the real lifecycle. */

void socksv5_pool_destroy(void) {
}

void socksv5_passive_accept(struct selector_key *key) {
    (void)key;
    (void)client_statbl;
}
