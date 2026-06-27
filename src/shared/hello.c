#include "hello.h"
#include "socks5.h"

void hello_parser_init(struct hello_parser *p) {
    p->state = hello_version;
    p->remaining = 0;
}

enum hello_state hello_consume(buffer *b, struct hello_parser *p, bool *error) {
    while (buffer_can_read(b)) {
        uint8_t byte = buffer_read(b);
        switch (p->state) {
            case hello_version:
                if (byte != SOCKS_VERSION) {
                    p->state = hello_error;
                    *error = true;
                } else {
                    p->state = hello_nmethods;
                }
                break;
            case hello_nmethods:
                if (byte == 0) {
                    p->state = hello_error;
                    *error = true;
                } else {
                    p->remaining = byte;
                    p->state = hello_methods;
                }
                break;
            case hello_methods:
                if (p->on_authentication_method != NULL) {
                    p->on_authentication_method(p, byte);
                }
                p->remaining--;
                if (p->remaining == 0) {
                    p->state = hello_done;
                }
                break;
            case hello_done:
            case hello_error:
                break;
        }
        if (p->state == hello_done || p->state == hello_error) {
            break;
        }
    }
    return p->state;
}

bool hello_is_done(enum hello_state state, bool *error) {
    if (state == hello_error) {
        if (error != NULL) {
            *error = true;
        }
        return true;
    }
    return state == hello_done;
}

int hello_marshall(buffer *b, uint8_t method) {
    size_t n;
    uint8_t *ptr = buffer_write_ptr(b, &n);
    if (n < 2) {
        return -1;
    }
    ptr[0] = SOCKS_VERSION;
    ptr[1] = method;
    buffer_write_adv(b, 2);
    return 0;
}
