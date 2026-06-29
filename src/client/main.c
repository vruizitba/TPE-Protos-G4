#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>

#define DEFAULT_MNG_ADDR "127.0.0.1"
#define DEFAULT_MNG_PORT "8080"
#define COMMAND_SIZE 1024
#define RESPONSE_SIZE 4096

static void
usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [-L addr] [-P port] [-a secret] <command>\n"
            "\n"
            "Commands:\n"
            "  stats\n"
            "  users\n"
            "  user set <name> <pass>\n"
            "  user delete <name>\n"
            "  config get\n"
            "  config set <key> <value>\n",
            prog);
}

static int
connect_to(const char *addr, const char *port)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *it;
    int fd = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int error = getaddrinfo(addr, port, &hints, &res);
    if (error != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error));
        return -1;
    }

    for (it = res; it != NULL; it = it->ai_next) {
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd < 0) {
            continue;
        }
        if (connect(fd, it->ai_addr, it->ai_addrlen) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static bool
send_all(int fd, const char *s)
{
    size_t sent = 0;
    size_t len = strlen(s);

    while (sent < len) {
        ssize_t n = send(fd, s + sent, len - sent, 0);
        if (n <= 0) {
            return false;
        }
        sent += (size_t)n;
    }
    return true;
}

static bool
read_line(int fd, char *buf, size_t len)
{
    size_t used = 0;

    while (used + 1 < len) {
        char c;
        ssize_t n = recv(fd, &c, 1, 0);
        if (n <= 0) {
            return false;
        }
        if (c == '\r') {
            continue;
        }
        if (c == '\n') {
            buf[used] = '\0';
            return true;
        }
        buf[used++] = c;
    }
    buf[used] = '\0';
    return true;
}

static bool
build_command(int argc, char **argv, char *out, size_t out_len)
{
    int n;

    if (argc == 1 && strcmp(argv[0], "stats") == 0) {
        n = snprintf(out, out_len, "STATS\n");
    } else if (argc == 1 && strcmp(argv[0], "users") == 0) {
        n = snprintf(out, out_len, "USERS\n");
    } else if (argc == 4 && strcmp(argv[0], "user") == 0
               && strcmp(argv[1], "set") == 0) {
        n = snprintf(out, out_len, "USER SET %s %s\n", argv[2], argv[3]);
    } else if (argc == 3 && strcmp(argv[0], "user") == 0
               && strcmp(argv[1], "delete") == 0) {
        n = snprintf(out, out_len, "USER DELETE %s\n", argv[2]);
    } else if (argc == 2 && strcmp(argv[0], "config") == 0
               && strcmp(argv[1], "get") == 0) {
        n = snprintf(out, out_len, "CONFIG GET\n");
    } else if (argc == 4 && strcmp(argv[0], "config") == 0
               && strcmp(argv[1], "set") == 0) {
        n = snprintf(out, out_len, "CONFIG SET %s %s\n", argv[2], argv[3]);
    } else {
        return false;
    }

    return n > 0 && (size_t)n < out_len;
}

int
main(int argc, char **argv)
{
    const char *addr = DEFAULT_MNG_ADDR;
    const char *port = DEFAULT_MNG_PORT;
    const char *secret = NULL;
    char command[COMMAND_SIZE];
    char response[RESPONSE_SIZE];
    int c;

    while ((c = getopt(argc, argv, "hL:P:a:")) != -1) {
        switch (c) {
        case 'h':
            usage(argv[0]);
            return 0;
        case 'L':
            addr = optarg;
            break;
        case 'P':
            port = optarg;
            break;
        case 'a':
            secret = optarg;
            break;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (!build_command(argc - optind, argv + optind, command, sizeof(command))) {
        usage(argv[0]);
        return 1;
    }

    int fd = connect_to(addr, port);
    if (fd < 0) {
        fprintf(stderr, "unable to connect to %s:%s: %s\n", addr, port, strerror(errno));
        return 1;
    }

    if (secret != NULL) {
        char auth[COMMAND_SIZE];
        int n = snprintf(auth, sizeof(auth), "AUTH %s\n", secret);
        if (n <= 0 || (size_t)n >= sizeof(auth) || !send_all(fd, auth)
            || !read_line(fd, response, sizeof(response))) {
            fprintf(stderr, "authentication exchange failed\n");
            close(fd);
            return 1;
        }
        if (strncmp(response, "+OK", 3) != 0) {
            fprintf(stderr, "%s\n", response);
            close(fd);
            return 1;
        }
    }

    if (!send_all(fd, command) || !read_line(fd, response, sizeof(response))) {
        fprintf(stderr, "command exchange failed\n");
        close(fd);
        return 1;
    }

    printf("%s\n", response);
    close(fd);
    return strncmp(response, "+OK", 3) == 0 ? 0 : 1;
}
