#include "auth.h"

void auth_parser_init(struct auth_parser *parser) {
    parser->state = auth_ver;
    parser->remaining = 0;
    parser->ulen = 0;
    parser->plen = 0;
}

enum auth_state auth_consume(buffer *buffer_ptr, struct auth_parser *parser, bool *error) {
    while (buffer_can_read(buffer_ptr)) {
        uint8_t byte = buffer_read(buffer_ptr);
        switch (parser->state) {
            case auth_ver:
                if (byte != AUTH_VERSION) {
                    parser->state = auth_error;
                    *error = true;
                } else {
                    parser->state = auth_ulen;
                }
                break;
            case auth_ulen:
                if (byte == 0) {
                    parser->state = auth_error;
                    *error = true;
                } else {
                    parser->ulen = byte;
                    parser->remaining = byte;
                    parser->state = auth_uname;
                }
                break;
            case auth_uname:
                parser->uname[parser->ulen - parser->remaining] = (char)byte;
                if (--parser->remaining == 0) {
                    parser->uname[parser->ulen] = '\0';
                    parser->state = auth_plen;
                }
                break;
            case auth_plen:
                if (byte == 0) {
                    parser->state = auth_error;
                    *error = true;
                } else {
                    parser->plen = byte;
                    parser->remaining = byte;
                    parser->state = auth_passwd;
                }
                break;
            case auth_passwd:
                parser->passwd[parser->plen - parser->remaining] = (char)byte;
                if (--parser->remaining == 0) {
                    parser->passwd[parser->plen] = '\0';
                    parser->state = auth_done;
                }
                break;
            case auth_done:
            case auth_error:
                break;
        }
        if (parser->state == auth_done || parser->state == auth_error) {
            break;
        }
    }
    return parser->state;
}

bool auth_is_done(enum auth_state state, bool *error) {
    if (state == auth_error) {
        if (error != NULL) {
            *error = true;
        }
        return true;
    }
    return state == auth_done;
}

int auth_marshall(buffer *buffer_ptr, uint8_t status) {
    size_t available;
    uint8_t *write_ptr = buffer_write_ptr(buffer_ptr, &available);
    if (available < 2) {
        return -1;
    }
    write_ptr[0] = AUTH_VERSION;
    write_ptr[1] = status;
    buffer_write_adv(buffer_ptr, 2);
    return 0;
}
