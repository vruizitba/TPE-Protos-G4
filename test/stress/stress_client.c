/* Opens N concurrent SOCKS5 tunnels (one thread per tunnel) against a
 * running socks5d, round-trips a small payload through each one, and
 * reports how many succeeded and how long the handshake took. All threads
 * synchronize on a barrier right after connecting, so the N tunnels are
 * genuinely open at the same time before any payload is exchanged. Tunnels
 * are split round-robin across the three SOCKS5 ATYPs (IPv4, IPv6, FQDN),
 * assuming the target (stress_echo) answers on 127.0.0.1, ::1 and
 * "localhost" alike. Not part of the graded server: a fixture for
 * `make stress`. */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

enum dest_kind { KIND_IPV4 = 0, KIND_IPV6, KIND_FQDN, KIND_COUNT };
static const char *const kind_name[KIND_COUNT] = { "ipv4", "ipv6", "fqdn" };

struct args {
    const char *socks_host;
    uint16_t socks_port;
    const char *user;
    const char *pass;
    const char *target_host;
    uint16_t target_port;
    int id;
    enum dest_kind kind;
};

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_barrier_t g_barrier;
static int g_ok;
static int g_fail;
static int g_ok_by_kind[KIND_COUNT];
static int g_fail_by_kind[KIND_COUNT];
static double g_open_sum;
static double g_open_max;

static double
now_seconds(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static int
read_exact(int fd, void *buf, size_t n)
{
    size_t got = 0;
    while (got < n) {
        ssize_t r = recv(fd, (char *)buf + got, n - got, 0);
        if (r <= 0) {
            return -1;
        }
        got += (size_t)r;
    }
    return 0;
}

static int
write_exact(int fd, const void *buf, size_t n)
{
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = send(fd, (const char *)buf + sent, n - sent, 0);
        if (w <= 0) {
            return -1;
        }
        sent += (size_t)w;
    }
    return 0;
}

/* Fills req[] with a CONNECT request for a->kind (IPv4/IPv6 literal or
 * FQDN "localhost"), all pointing at the same dual-stack stress_echo
 * target. Returns the request length, or 0 on a malformed literal. */
static size_t
build_connect_request(uint8_t *req, const struct args *a)
{
    size_t n = 4;
    req[0] = 0x05;
    req[1] = 0x01;
    req[2] = 0x00;

    switch (a->kind) {
    case KIND_IPV4: {
        struct in_addr addr4;
        if (inet_pton(AF_INET, a->target_host, &addr4) != 1) {
            return 0;
        }
        req[3] = 0x01;
        memcpy(req + n, &addr4, sizeof(addr4));
        n += sizeof(addr4);
        break;
    }
    case KIND_IPV6: {
        struct in6_addr addr6;
        if (inet_pton(AF_INET6, "::1", &addr6) != 1) {
            return 0;
        }
        req[3] = 0x04;
        memcpy(req + n, &addr6, sizeof(addr6));
        n += sizeof(addr6);
        break;
    }
    default: {
        const char *fqdn = "localhost";
        size_t len = strlen(fqdn);
        req[3] = 0x03;
        req[n++] = (uint8_t)len;
        memcpy(req + n, fqdn, len);
        n += len;
        break;
    }
    }

    uint16_t port_be = htons(a->target_port);
    memcpy(req + n, &port_be, sizeof(port_be));
    n += sizeof(port_be);
    return n;
}

/* Connects and completes the SOCKS5 handshake. Returns true and leaves the
 * tunnel established on success; on any failure returns false (fd is still
 * open, caller closes it after the barrier either way). */
static bool
open_tunnel(int fd, const struct args *a)
{
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(a->socks_port);
    inet_pton(AF_INET, a->socks_host, &addr.sin_addr);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        return false;
    }

    uint8_t hello[3] = { 0x05, 0x01, 0x02 };
    uint8_t hello_reply[2];
    if (write_exact(fd, hello, sizeof(hello)) < 0
        || read_exact(fd, hello_reply, sizeof(hello_reply)) < 0
        || hello_reply[0] != 0x05 || hello_reply[1] != 0x02) {
        return false;
    }

    uint8_t auth[512];
    size_t ulen = strlen(a->user), plen = strlen(a->pass);
    size_t alen = 0;
    auth[alen++] = 0x01;
    auth[alen++] = (uint8_t)ulen;
    memcpy(auth + alen, a->user, ulen);
    alen += ulen;
    auth[alen++] = (uint8_t)plen;
    memcpy(auth + alen, a->pass, plen);
    alen += plen;
    uint8_t auth_reply[2];
    if (write_exact(fd, auth, alen) < 0
        || read_exact(fd, auth_reply, sizeof(auth_reply)) < 0
        || auth_reply[1] != 0x00) {
        return false;
    }

    uint8_t req[262];
    size_t reqlen = build_connect_request(req, a);
    if (reqlen == 0) {
        return false;
    }
    uint8_t reply[10]; /* server always replies ATYP=IPv4, BND=0.0.0.0:0 */
    if (write_exact(fd, req, reqlen) < 0
        || read_exact(fd, reply, sizeof(reply)) < 0 || reply[1] != 0x00) {
        return false;
    }

    return true;
}

static bool
echo_roundtrip(int fd, int id)
{
    char payload[64];
    int len = snprintf(payload, sizeof(payload), "ping-%d\n", id);
    char echoed[64];
    return write_exact(fd, payload, (size_t)len) == 0
        && read_exact(fd, echoed, (size_t)len) == 0
        && memcmp(payload, echoed, (size_t)len) == 0;
}

static void *
run_tunnel(void *arg)
{
    struct args *a = arg;
    double start = now_seconds();
    double open_seconds = 0;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd >= 0) {
        struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }
    bool connected = fd >= 0 && open_tunnel(fd, a);
    if (connected) {
        open_seconds = now_seconds() - start;
    }

    /* Every thread reaches this point (connected or not) so that up to N
     * tunnels are genuinely open at the same time before any of them
     * exchanges a payload and closes. */
    pthread_barrier_wait(&g_barrier);

    bool ok = connected && echo_roundtrip(fd, a->id);

    if (fd >= 0) {
        close(fd);
    }

    pthread_mutex_lock(&g_lock);
    if (ok) {
        g_ok++;
        g_ok_by_kind[a->kind]++;
        g_open_sum += open_seconds;
        if (open_seconds > g_open_max) {
            g_open_max = open_seconds;
        }
    } else {
        g_fail++;
        g_fail_by_kind[a->kind]++;
    }
    pthread_mutex_unlock(&g_lock);

    free(a);
    return NULL;
}

int
main(int argc, char *argv[])
{
    if (argc != 8) {
        fprintf(stderr,
                "usage: %s <socks_host> <socks_port> <user> <pass> "
                "<target_host> <target_port> <n_tunnels>\n",
                argv[0]);
        return 1;
    }
    const char *socks_host = argv[1];
    uint16_t socks_port = (uint16_t)atoi(argv[2]);
    const char *user = argv[3];
    const char *pass = argv[4];
    const char *target_host = argv[5];
    uint16_t target_port = (uint16_t)atoi(argv[6]);
    int n = atoi(argv[7]);

    if (pthread_barrier_init(&g_barrier, NULL, (unsigned)n) != 0) {
        perror("pthread_barrier_init");
        return 1;
    }

    pthread_t *threads = malloc(sizeof(pthread_t) * (size_t)n);
    if (threads == NULL) {
        perror("malloc");
        return 1;
    }

    double start = now_seconds();
    for (int i = 0; i < n; i++) {
        struct args *a = malloc(sizeof(*a));
        a->socks_host = socks_host;
        a->socks_port = socks_port;
        a->user = user;
        a->pass = pass;
        a->target_host = target_host;
        a->target_port = target_port;
        a->id = i;
        a->kind = (enum dest_kind)(i % KIND_COUNT);
        if (pthread_create(&threads[i], NULL, run_tunnel, a) != 0) {
            fprintf(stderr, "pthread_create failed at thread %d, aborting\n", i);
            free(a);
            return 1;
        }
    }
    for (int i = 0; i < n; i++) {
        pthread_join(threads[i], NULL);
    }
    double total = now_seconds() - start;

    printf("requested=%d ok=%d failed=%d wall_time=%.3fs\n",
           n, g_ok, g_fail, total);
    if (g_ok > 0) {
        printf("open_time avg=%.3fs max=%.3fs\n", g_open_sum / g_ok, g_open_max);
    }
    for (int k = 0; k < KIND_COUNT; k++) {
        printf("  %s: ok=%d failed=%d\n", kind_name[k], g_ok_by_kind[k], g_fail_by_kind[k]);
    }

    free(threads);
    pthread_barrier_destroy(&g_barrier);
    return g_fail > 0 ? 1 : 0;
}
