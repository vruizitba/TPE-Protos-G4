#include <string.h>
#include "request.h"
#include "socks5.h"

void
request_parser_init(struct request_parser *p)
{
    p->state = request_version;
    p->remaining = 0;
    p->read = 0;
}

enum request_state
request_consume(buffer *b, struct request_parser *p, bool *error)
{
    while (buffer_can_read(b)) {
        uint8_t byte = buffer_read(b);
        switch (p->state) {
            case request_version:
                if (byte != SOCKS_VERSION) {
                    p->state = request_error;
                    if (error != NULL) {
                        *error = true;
                    }
                } else {
                    p->state = request_cmd;
                }
                break;

            case request_cmd:
                p->request->cmd = byte;
                if (byte != SOCKS_CMD_CONNECT) {
                    p->state = request_error_unsupported_cmd;
                } else {
                    p->state = request_rsv;
                }
                break;

            case request_rsv:
                p->state = request_atyp;
                break;

            case request_atyp:
                p->request->dest_addr.type = byte;
                p->read = 0;
                if (byte == SOCKS_ATYP_IPV4) {
                    p->remaining = SOCKS_ATYP_IPV4_LEN;
                    p->state = request_dst_addr;
                } else if (byte == SOCKS_ATYP_IPV6) {
                    p->remaining = SOCKS_ATYP_IPV6_LEN;
                    p->state = request_dst_addr;
                } else if (byte == SOCKS_ATYP_FQDN) {
                    p->remaining = 0; /* length byte not yet read */
                    p->state = request_dst_addr;
                } else {
                    p->state = request_error_unsupported_atyp;
                }
                break;

            case request_dst_addr:
                if (p->request->dest_addr.type == SOCKS_ATYP_FQDN && p->remaining == 0) {
                    if (byte == 0) {
                        p->state = request_error;
                        if (error != NULL) {
                            *error = true;
                        }
                        break;
                    }
                    p->remaining = byte;
                    p->read = 0;
                } else if (p->request->dest_addr.type == SOCKS_ATYP_IPV4) {
                    ((uint8_t *)&p->request->dest_addr.ipv4)[p->read++] = byte;
                    if (--p->remaining == 0) {
                        p->state = request_dst_port;
                        p->read = 0;
                    }
                } else if (p->request->dest_addr.type == SOCKS_ATYP_IPV6) {
                    ((uint8_t *)&p->request->dest_addr.ipv6)[p->read++] = byte;
                    if (--p->remaining == 0) {
                        p->state = request_dst_port;
                        p->read = 0;
                    }
                } else {
                    /* FQDN, length > 0 */
                    if (p->read >= MAX_FQDN_LEN) {
                        p->state = request_error;
                        if (error != NULL) {
                            *error = true;
                        }
                        break;
                    }
                    p->request->dest_addr.fqdn[p->read++] = (char)byte;
                    if (--p->remaining == 0) {
                        p->request->dest_addr.fqdn[p->read] = '\0';
                        p->state = request_dst_port;
                        p->read = 0;
                    }
                }
                break;

            case request_dst_port:
                if (p->read == 0) {
                    p->request->dest_port = (uint16_t)byte << 8;
                    p->read++;
                } else {
                    p->request->dest_port |= byte;
                    p->state = request_done;
                    p->read = 0;
                }
                break;

            case request_done:
            case request_error:
            case request_error_unsupported_atyp:
            case request_error_unsupported_cmd:
                break;
        }
        if (p->state == request_done ||
            p->state == request_error ||
            p->state == request_error_unsupported_atyp ||
            p->state == request_error_unsupported_cmd) {
            break;
        }
    }
    return p->state;
}

bool
request_is_done(enum request_state state, bool *error)
{
    switch (state) {
        case request_done:
            return true;
        case request_error:
            if (error != NULL) {
                *error = true;
            }
            return true;
        case request_error_unsupported_atyp:
        case request_error_unsupported_cmd:
            return true;
        default:
            return false;
    }
}

int
request_marshall(buffer *b, uint8_t reply)
{
    size_t available;
    uint8_t *write_ptr = buffer_write_ptr(b, &available);
    if (available < 10) {
        return -1;
    }
    write_ptr[0] = SOCKS_VERSION;
    write_ptr[1] = reply;
    write_ptr[2] = SOCKS_RSV;
    write_ptr[3] = SOCKS_ATYP_IPV4;
    write_ptr[4] = 0;              /* BND.ADDR: 0.0.0.0 */
    write_ptr[5] = 0;
    write_ptr[6] = 0;
    write_ptr[7] = 0;
    write_ptr[8] = 0;              /* BND.PORT: 0 */
    write_ptr[9] = 0;
    buffer_write_adv(b, 10);
    return 0;
}
