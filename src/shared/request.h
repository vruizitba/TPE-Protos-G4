#ifndef REQUEST_H
#define REQUEST_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include "buffer.h"

#define MAX_FQDN_LEN 255

enum request_state {
    request_version,
    request_cmd,
    request_rsv,
    request_atyp,
    request_dst_addr,
    request_dst_port,
    request_done,
    request_error,
    request_error_unsupported_atyp,
};

struct request_addr {
    uint8_t type; /* SOCKS_ATYP_* */
    union {
        struct in_addr ipv4;
        struct in6_addr ipv6;
        char fqdn[MAX_FQDN_LEN + 1];
    };
};

struct socks5_request {
    uint8_t cmd;
    struct request_addr dest_addr;
    uint16_t dest_port;
};

struct request_parser {
    struct socks5_request *request;
    enum request_state state;
    /* private */
    uint8_t remaining;
    uint8_t read;
};

void request_parser_init(struct request_parser *p);
enum request_state request_consume(buffer *b, struct request_parser *p, bool *error);
bool request_is_done(enum request_state state, bool *error);
int request_marshall(buffer *b, uint8_t reply);

#endif
