#include "hello.h"
#include "socks5.h"

void hello_parser_init(struct hello_parser *parser) {
    parser->state = hello_version;
    parser->remaining = 0;
}

enum hello_state hello_consume(buffer *buffer_ptr, struct hello_parser *parser, bool *error) {
    while (buffer_can_read(buffer_ptr)) {
        uint8_t byte = buffer_read(buffer_ptr);
        switch (parser->state) {
            case hello_version:
                if (byte != SOCKS_VERSION) {
                    parser->state = hello_error;
                    *error = true;
                } else {
                    parser->state = hello_nmethods;
                }
                break;
            case hello_nmethods:
                if (byte == 0) {
                    parser->state = hello_error;
                    *error = true;
                } else {
                    parser->remaining = byte;
                    parser->state = hello_methods;
                }
                break;
            case hello_methods:
                if (parser->on_authentication_method != NULL) {
                    parser->on_authentication_method(parser, byte);
                }
                parser->remaining--;
                if (parser->remaining == 0) {
                    parser->state = hello_done;
                }
                break;
            case hello_done:
            case hello_error:
                break;
        }
        if (parser->state == hello_done || parser->state == hello_error) {
            break;
        }
    }
    return parser->state;
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

int hello_marshall(buffer *buffer_ptr, uint8_t method) {
    size_t available;
    uint8_t *write_ptr = buffer_write_ptr(buffer_ptr, &available);
    if (available < 2) {
        return -1;
    }
    write_ptr[0] = SOCKS_VERSION;
    write_ptr[1] = method;
    buffer_write_adv(buffer_ptr, 2);
    return 0;
}
