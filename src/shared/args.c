#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include "args.h"

static unsigned short
port(const char *s)
{
    char *end = 0;
    const long sl = strtol(s, &end, 10);

    if (end == s || '\0' != *end
        || ((LONG_MIN == sl || LONG_MAX == sl) && ERANGE == errno)
        || sl < 0 || sl > USHRT_MAX)
    {
        fprintf(stderr, "port should be in the range of 1-65535: %s\n", s);
        exit(1);
    }
    return (unsigned short)sl;
}

static int
nonneg_int(const char *s, const char *flag)
{
    char *end = 0;
    const long sl = strtol(s, &end, 10);

    if (end == s || '\0' != *end || sl < 0 || sl > INT_MAX)
    {
        fprintf(stderr, "%s requires a non-negative integer: %s\n", flag, s);
        exit(1);
    }
    return (int)sl;
}

static void
user(char *s, struct users *u)
{
    char *p = strchr(s, ':');
    if (p == NULL)
    {
        fprintf(stderr, "user format must be name:password\n");
        exit(1);
    }
    *p = 0;
    u->name = s;
    u->pass = p + 1;
}

static void
version(void)
{
    fprintf(stderr, "socks5d version 0.1\n"
            "ITBA Protocolos de Comunicación 2026/1 -- Grupo 4\n");
}

static void
usage(const char *progname)
{
    fprintf(stderr,
        "Usage: %s [OPTION]...\n"
        "\n"
        "   -h               Imprime la ayuda y termina.\n"
        "   -l <SOCKS addr>  Dirección donde servirá el proxy SOCKS. Default: 0.0.0.0\n"
        "   -p <SOCKS port>  Puerto SOCKS. Default: 1080\n"
        "   -L <mgmt addr>   Dirección del servicio de management. Default: 127.0.0.1\n"
        "   -P <mgmt port>   Puerto de management. Default: 8080\n"
        "   -u <name>:<pass> Usuario SOCKS (repetible, hasta %d).\n"
        "   -a <secret>      Credencial de acceso al management.\n"
        "   -m <n>           Máximo de conexiones concurrentes (0 = sin límite).\n"
        "   -t <s>           Timeout de negociación en segundos (0 = deshabilitado).\n"
        "   -c <s>           Timeout de conexión a origen en segundos (0 = deshabilitado).\n"
        "   -i <s>           Timeout idle en segundos (0 = deshabilitado).\n"
        "   -o <file>        Archivo de access log (default: stderr).\n"
        "   -N               Deshabilitar dissectors.\n"
        "   -v               Imprime la versión y termina.\n"
        "\n",
        progname, MAX_USERS);
    exit(1);
}

void
parse_args(const int argc, char **argv, struct socks5args *args)
{
    memset(args, 0, sizeof(*args));

    args->socks_addr = "0.0.0.0";
    args->socks_port = 1080;

    args->mng_addr = "127.0.0.1";
    args->mng_port = 8080;
    args->dissectors_enabled = true;

    int c;
    int nusers = 0;

    while (true)
    {
        int option_index = 0;
        static struct option long_options[] = {
            {0, 0, 0, 0}
        };

        c = getopt_long(argc, argv, "hl:L:Np:P:u:a:m:t:c:i:o:v", long_options, &option_index);
        if (c == -1)
            break;

        switch (c)
        {
        case 'h':
            usage(argv[0]);
            break;
        case 'l':
            args->socks_addr = optarg;
            break;
        case 'L':
            args->mng_addr = optarg;
            break;
        case 'N':
            args->dissectors_enabled = false;
            break;
        case 'p':
            args->socks_port = port(optarg);
            break;
        case 'P':
            args->mng_port = port(optarg);
            break;
        case 'u':
            if (nusers >= MAX_USERS)
            {
                fprintf(stderr, "maximum number of users reached: %d\n", MAX_USERS);
                exit(1);
            }
            user(optarg, args->users + nusers++);
            break;
        case 'a':
            args->admin_secret = optarg;
            break;
        case 'm':
            args->max_connections = nonneg_int(optarg, "-m");
            break;
        case 't':
            args->negotiation_timeout = nonneg_int(optarg, "-t");
            break;
        case 'c':
            args->connect_timeout = nonneg_int(optarg, "-c");
            break;
        case 'i':
            args->idle_timeout = nonneg_int(optarg, "-i");
            break;
        case 'o':
            args->access_log = optarg;
            break;
        case 'v':
            version();
            exit(0);
        default:
            fprintf(stderr, "unknown argument %d\n", c);
            exit(1);
        }
    }

    if (optind < argc)
    {
        fprintf(stderr, "argument not accepted: ");
        while (optind < argc)
        {
            fprintf(stderr, "%s ", argv[optind++]);
        }
        fprintf(stderr, "\n");
        exit(1);
    }
}
