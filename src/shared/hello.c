#include "hello.h"

void
hello_parser_init(struct hello_parser *p)
{
    (void)p;
}

enum hello_state
hello_consume(buffer *b, struct hello_parser *p, bool *error)
{
    (void)b;
    (void)p;
    (void)error;
    return hello_error;
}

bool
hello_is_done(enum hello_state state, bool *error)
{
    (void)state;
    (void)error;
    return false;
}

int
hello_marshall(buffer *b, uint8_t method)
{
    (void)b;
    (void)method;
    return -1;
}
