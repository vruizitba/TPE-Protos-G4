/* Minimal blocking TCP echo server used as the stress test target. Not part
 * of the graded server: just a fixture so stress_client has somewhere to
 * open tunnels to and verify that bytes actually round-trip. Listens on a
 * dual-stack IPv6 socket so the same port answers 127.0.0.1, ::1 and
 * "localhost", letting stress_client exercise all three SOCKS5 ATYPs. */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static void
handle_client(int fd)
{
    char buf[4096];
    ssize_t n;
    while ((n = recv(fd, buf, sizeof(buf), 0)) > 0) {
        ssize_t sent = 0;
        while (sent < n) {
            ssize_t w = send(fd, buf + sent, (size_t)(n - sent), 0);
            if (w <= 0) {
                close(fd);
                return;
            }
            sent += w;
        }
    }
    close(fd);
}

int
main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <port>\n", argv[0]);
        return 1;
    }
    signal(SIGCHLD, SIG_IGN);

    int listen_fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        return 1;
    }
    int one = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    int v6only = 0;
    setsockopt(listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));

    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_any;
    addr.sin6_port = htons((uint16_t)atoi(argv[1]));

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }
    if (listen(listen_fd, 1024) < 0) {
        perror("listen");
        return 1;
    }

    fprintf(stderr, "stress echo server listening on [::]:%s (dual-stack)\n", argv[1]);

    while (1) {
        int client = accept(listen_fd, NULL, NULL);
        if (client < 0) {
            continue;
        }
        pid_t pid = fork();
        if (pid == 0) {
            close(listen_fd);
            handle_client(client);
            _exit(0);
        }
        close(client);
    }
}
