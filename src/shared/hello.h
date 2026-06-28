#ifndef HELLO_H
#define HELLO_H

#include <stdint.h>
#include <stdbool.h>
#include "buffer.h"

/* RFC1928 client greeting parser */

enum hello_state {
    hello_version,
    hello_nmethods,
    hello_methods,
    hello_done,
    hello_error,
};

struct hello_parser {
    void (*on_authentication_method)(struct hello_parser *p, uint8_t method);
    void *data;
    /* private */
    enum hello_state state;
    uint8_t remaining;
};

void hello_parser_init(struct hello_parser *parser);
enum hello_state hello_consume(buffer *buffer_ptr, struct hello_parser *parser, bool *error);
bool hello_is_done(enum hello_state state, bool *error);
int hello_marshall(buffer *buffer_ptr, uint8_t method);

#endif
