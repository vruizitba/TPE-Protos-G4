/**
 * main.c - servidor proxy SOCKS5
 *
 * Interpreta los argumentos de línea de comandos, crea sockets pasivos para
 * SOCKS5 y management, registra señales y corre el event loop del selector.
 * Todas las conexiones se atienden en este único hilo; la resolución DNS se
 * delega a threads de bloqueo vía el mecanismo block del selector.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "args.h"
#include "config.h"
#include "dns_worker.h"
#include "metrics.h"
#include "selector.h"
#include "socks5nio.h"
#include "mng.h"
#include "users.h"
#include "access_log.h"

#define LISTEN_BACKLOG 20
#define SELECTOR_TIMEOUT_SECS 10
#define SELECTOR_MAX_FDS 1024
#define PORT_STR_LEN 6

static volatile sig_atomic_t signal_count = 0;

static void
sigterm_handler(const int signal)
{
    (void)signal;
    signal_count++;
}

static void
cleanup(fd_selector selector, int socks_fd, int mng_fd, users_t *users,
        metrics_t *metrics, dns_worker_t *dns_worker, access_log_t *access_log)
{
    dns_worker_destroy(dns_worker);
    if (selector != NULL) {
        selector_destroy(selector);
    }
    selector_close();
    socksv5_pool_destroy();
    mng_pool_destroy();
    if (socks_fd >= 0) {
        close(socks_fd);
    }
    if (mng_fd >= 0) {
        close(mng_fd);
    }
    users_destroy(users);
    metrics_destroy(metrics);

    access_log_destroy(access_log);
}

static int
passive_socket(const char *addr, unsigned short port)
{
    char port_str[PORT_STR_LEN];
    snprintf(port_str, sizeof(port_str), "%hu", port);

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

    int r = getaddrinfo(addr, port_str, &hints, &res);
    if (r != 0) {
        fprintf(stderr, "getaddrinfo(%s:%hu): %s\n", addr, port, gai_strerror(r));
        return -1;
    }

    int fd = socket(res->ai_family, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        perror("socket");
        freeaddrinfo(res);
        return -1;
    }

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

    if (bind(fd, res->ai_addr, res->ai_addrlen) < 0) {
        perror("bind");
        freeaddrinfo(res);
        close(fd);
        return -1;
    }
    freeaddrinfo(res);

    if (listen(fd, LISTEN_BACKLOG) < 0) {
        perror("listen");
        close(fd);
        return -1;
    }

    return fd;
}

int
main(const int argc, const char **argv)
{
    struct socks5args args;
    parse_args(argc, (char **)argv, &args);

    close(0); /* nothing to read from stdin */

    users_t *users = users_create();
    metrics_t *metrics = metrics_create();
    config_t config;
    access_log_t *access_log = access_log_create(args.access_log);
    config_init(&config);
    config_set_defaults(&config, args.negotiation_timeout, args.connect_timeout,
                        args.idle_timeout, args.max_connections);

    if (users == NULL || metrics == NULL || access_log == NULL) {
        fprintf(stderr, "unable to allocate shared state\n");
        cleanup(NULL, -1, -1, users, metrics, NULL, access_log);
        return 1;
    }
    for (int i = 0; i < MAX_USERS && args.users[i].name != NULL; i++) {
        if (!users_add(users, args.users[i].name, args.users[i].pass)) {
            fprintf(stderr, "unable to add configured user: %s\n", args.users[i].name);
            cleanup(NULL, -1, -1, users, metrics, NULL, access_log);
            return 1;
        }
    }

    fd_selector selector = NULL;
    int socks_fd = -1;
    int mng_fd = -1;
    dns_worker_t *dns_worker = NULL;
    bool draining = false;

    socks_fd = passive_socket(args.socks_addr, args.socks_port);
    if (socks_fd < 0) {
        cleanup(NULL, -1, -1, users, metrics, NULL, access_log);
        return 1;
    }
    fprintf(stdout, "SOCKS5 listening on %s:%hu\n", args.socks_addr, args.socks_port);

    mng_fd = passive_socket(args.mng_addr, args.mng_port);
    if (mng_fd < 0) {
        cleanup(NULL, socks_fd, -1, users, metrics, NULL, access_log);
        return 1;
    }
    fprintf(stdout, "Management listening on %s:%hu\n", args.mng_addr, args.mng_port);

    signal(SIGTERM, sigterm_handler);
    signal(SIGINT, sigterm_handler);

    if (selector_fd_set_nio(socks_fd) == -1 || selector_fd_set_nio(mng_fd) == -1) {
        perror("setting non-blocking mode");
        cleanup(NULL, socks_fd, mng_fd, users, metrics, NULL, access_log);
        return 1;
    }

    const struct selector_init conf = {
        .signal = SIGALRM,
        .select_timeout = { .tv_sec = SELECTOR_TIMEOUT_SECS, .tv_nsec = 0 },
    };
    if (selector_init(&conf) != 0) {
        perror("initializing selector");
        cleanup(NULL, socks_fd, mng_fd, users, metrics, NULL, access_log);
        return 1;
    }

    selector = selector_new(SELECTOR_MAX_FDS);
    if (selector == NULL) {
        perror("unable to create selector");
        cleanup(NULL, socks_fd, mng_fd, users, metrics, NULL, access_log);
        return 1;
    }

    dns_worker = dns_worker_create();
    if (dns_worker == NULL) {
        fprintf(stderr, "unable to create DNS worker\n");
        cleanup(selector, socks_fd, mng_fd, users, metrics, NULL, access_log);
        return 1;
    }

    socksv5_set_users(users);
    socksv5_set_metrics(metrics);
    socksv5_set_dns_worker(dns_worker);
    socksv5_set_access_log(access_log);
    mng_set_context(args.admin_secret, users, metrics, &config);

    const struct fd_handler socks_handler = {
        .handle_read = socksv5_passive_accept,
        .handle_write = NULL,
        .handle_close = NULL,
    };
    selector_status ss = selector_register(selector, socks_fd, &socks_handler, OP_READ, NULL);
    if (ss != SELECTOR_SUCCESS) {
        fprintf(stderr, "registering SOCKS5 fd: %s\n",
                ss == SELECTOR_IO ? strerror(errno) : selector_error(ss));
        cleanup(selector, socks_fd, mng_fd, users, metrics, dns_worker, access_log);
        return 1;
    }

    const struct fd_handler mng_handler = {
        .handle_read = mng_passive_accept,
        .handle_write = NULL,
        .handle_close = NULL,
    };
    ss = selector_register(selector, mng_fd, &mng_handler, OP_READ, NULL);
    if (ss != SELECTOR_SUCCESS) {
        fprintf(stderr, "registering management fd: %s\n",
                ss == SELECTOR_IO ? strerror(errno) : selector_error(ss));
        cleanup(selector, socks_fd, mng_fd, users, metrics, dns_worker, access_log);
        return 1;
    }

    while (true) {
        if (signal_count > 1) {
            fprintf(stdout, "second signal received, forcing shutdown\n");
            break;
        }
        if (signal_count == 1 && !draining) {
            fprintf(stdout, "signal received, draining active sessions\n");
            if (socks_fd >= 0) {
                selector_unregister_fd(selector, socks_fd);
                close(socks_fd);
                socks_fd = -1;
            }
            if (mng_fd >= 0) {
                selector_unregister_fd(selector, mng_fd);
                close(mng_fd);
                mng_fd = -1;
            }
            draining = true;
        }
        if (draining && socksv5_active_sessions() == 0
            && mng_active_sessions() == 0) {
            break;
        }

        ss = selector_select(selector);
        if (ss != SELECTOR_SUCCESS) {
            fprintf(stderr, "serving: %s\n",
                    ss == SELECTOR_IO ? strerror(errno) : selector_error(ss));
            cleanup(selector, socks_fd, mng_fd, users, metrics, dns_worker, access_log);
            return 1;
        }
    }

    cleanup(selector, socks_fd, mng_fd, users, metrics, dns_worker, access_log);
    return 0;
}
