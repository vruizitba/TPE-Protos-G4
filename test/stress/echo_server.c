/* Minimal blocking TCP echo server used as the stress test target. Not part
 * of the graded server: just a fixture so stress_client has somewhere to
 * open tunnels to and verify that bytes actually round-trip. */
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

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        return 1;
    }
    int one = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((uint16_t)atoi(argv[1]));

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }
    if (listen(listen_fd, 1024) < 0) {
        perror("listen");
        return 1;
    }

    fprintf(stderr, "stress echo server listening on 127.0.0.1:%s\n", argv[1]);

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
