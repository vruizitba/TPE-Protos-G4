#include "request.h"

void
request_parser_init(struct request_parser *p)
{
    (void)p;
}

enum request_state
request_consume(buffer *b, struct request_parser *p, bool *error)
{
    (void)b;
    (void)p;
    (void)error;
    return request_error;
}

bool
request_is_done(enum request_state state, bool *error)
{
    (void)state;
    (void)error;
    return false;
}

int
request_marshall(buffer *b, uint8_t reply)
{
    (void)b;
    (void)reply;
    return -1;
}
