#ifndef AUTH_H
#define AUTH_H

#include <stdint.h>
#include <stdbool.h>
#include "buffer.h"

#define AUTH_VERSION 0x01

enum auth_state {
    auth_ver,
    auth_ulen,
    auth_uname,
    auth_plen,
    auth_passwd,
    auth_done,
    auth_error,
};

struct auth_parser {
    enum auth_state state;
    uint8_t remaining;
    uint8_t ulen;
    uint8_t plen;
    char uname[256];
    char passwd[256];
};

void auth_parser_init(struct auth_parser *parser);
enum auth_state auth_consume(buffer *buffer_ptr, struct auth_parser *parser, bool *error);
bool auth_is_done(enum auth_state state, bool *error);
int auth_marshall(buffer *buffer_ptr, uint8_t status);

#endif
