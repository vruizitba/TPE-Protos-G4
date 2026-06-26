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
#include "selector.h"
#include "socks5nio.h"
#include "mng.h"

#define LISTEN_BACKLOG 20
#define SELECTOR_TIMEOUT_SECS 10
#define SELECTOR_MAX_FDS 1024
#define PORT_STR_LEN 6

static bool done = false;

static void
sigterm_handler(const int signal)
{
    printf("signal %d, cleaning up and exiting\n", signal);
    done = true;
}

static void
cleanup(fd_selector selector, int socks_fd, int mng_fd)
{
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

    fd_selector selector = NULL;
    int socks_fd = -1;
    int mng_fd = -1;

    socks_fd = passive_socket(args.socks_addr, args.socks_port);
    if (socks_fd < 0) {
        return 1;
    }
    fprintf(stdout, "SOCKS5 listening on %s:%hu\n", args.socks_addr, args.socks_port);

    mng_fd = passive_socket(args.mng_addr, args.mng_port);
    if (mng_fd < 0) {
        cleanup(NULL, socks_fd, -1);
        return 1;
    }
    fprintf(stdout, "Management listening on %s:%hu\n", args.mng_addr, args.mng_port);

    signal(SIGTERM, sigterm_handler);
    signal(SIGINT, sigterm_handler);

    if (selector_fd_set_nio(socks_fd) == -1 || selector_fd_set_nio(mng_fd) == -1) {
        perror("setting non-blocking mode");
        cleanup(NULL, socks_fd, mng_fd);
        return 1;
    }

    const struct selector_init conf = {
        .signal = SIGALRM,
        .select_timeout = { .tv_sec = SELECTOR_TIMEOUT_SECS, .tv_nsec = 0 },
    };
    if (selector_init(&conf) != 0) {
        perror("initializing selector");
        cleanup(NULL, socks_fd, mng_fd);
        return 1;
    }

    selector = selector_new(SELECTOR_MAX_FDS);
    if (selector == NULL) {
        perror("unable to create selector");
        cleanup(NULL, socks_fd, mng_fd);
        return 1;
    }

    const struct fd_handler socks_handler = {
        .handle_read = socksv5_passive_accept,
        .handle_write = NULL,
        .handle_close = NULL,
    };
    selector_status ss = selector_register(selector, socks_fd, &socks_handler, OP_READ, NULL);
    if (ss != SELECTOR_SUCCESS) {
        fprintf(stderr, "registering SOCKS5 fd: %s\n",
                ss == SELECTOR_IO ? strerror(errno) : selector_error(ss));
        cleanup(selector, socks_fd, mng_fd);
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
        cleanup(selector, socks_fd, mng_fd);
        return 1;
    }

    while (!done) {
        ss = selector_select(selector);
        if (ss != SELECTOR_SUCCESS) {
            fprintf(stderr, "serving: %s\n",
                    ss == SELECTOR_IO ? strerror(errno) : selector_error(ss));
            cleanup(selector, socks_fd, mng_fd);
            return 1;
        }
    }

    cleanup(selector, socks_fd, mng_fd);
    return 0;
}
