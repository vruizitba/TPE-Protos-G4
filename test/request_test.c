#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <check.h>

#include "request.h"
#include "netutils.h"
#include "socks5.h"

#define TEST_BUF_SIZE 512
#define TEST_FQDN_HOST_LEN 11  /* strlen("example.com") */

/* Feed a raw byte array into the parser through a stack-allocated buffer. */
static enum request_state
parse(struct request_parser *p, const uint8_t *data, size_t n, bool *error)
{
    uint8_t raw[TEST_BUF_SIZE];
    struct buffer b;
    buffer_init(&b, sizeof(raw), raw);

    size_t avail;
    uint8_t *wp = buffer_write_ptr(&b, &avail);
    if (n > avail) {
        n = avail;
    }
    memcpy(wp, data, n);
    buffer_write_adv(&b, n);

    return request_consume(&b, p, error);
}

static void
init_parser(struct request_parser *p, struct socks5_request *req)
{
    memset(req, 0, sizeof(*req));
    p->request = req;
    request_parser_init(p);
}

/* ── IPv4 ──────────────────────────────────────────────────────────────── */

START_TEST(test_ipv4_connect)
{
    struct socks5_request req;
    struct request_parser p;
    init_parser(&p, &req);
    bool error = false;

    uint8_t msg[] = {
        SOCKS_VERSION,      /* VER */
        SOCKS_CMD_CONNECT,  /* CMD */
        SOCKS_RSV,          /* RSV */
        SOCKS_ATYP_IPV4,    /* ATYP */
        192, 168, 1, 1,     /* ADDR(4): 192.168.1.1 */
        0x00, 0x50          /* PORT(2): 80 */
    };
    enum request_state st = parse(&p, msg, sizeof(msg), &error);

    ck_assert_int_eq(st, request_done);
    ck_assert_int_eq(error, false);
    ck_assert_int_eq(req.cmd, SOCKS_CMD_CONNECT);
    ck_assert_int_eq(req.dest_addr.type, SOCKS_ATYP_IPV4);
    ck_assert_int_eq(req.dest_port, 80);

    struct in_addr expected;
    inet_pton(AF_INET, "192.168.1.1", &expected);
    ck_assert_mem_eq(&req.dest_addr.ipv4, &expected, sizeof(expected));
}
END_TEST

/* ── IPv6 ──────────────────────────────────────────────────────────────── */

START_TEST(test_ipv6_connect)
{
    struct socks5_request req;
    struct request_parser p;
    init_parser(&p, &req);
    bool error = false;

    uint8_t msg[] = {
        SOCKS_VERSION,                          /* VER */
        SOCKS_CMD_CONNECT,                      /* CMD */
        SOCKS_RSV,                              /* RSV */
        SOCKS_ATYP_IPV6,                        /* ATYP */
        0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1,     /* ADDR(16): ::1 */
        0x01, 0xBB                              /* PORT(2): 443 */
    };
    enum request_state st = parse(&p, msg, sizeof(msg), &error);

    ck_assert_int_eq(st, request_done);
    ck_assert_int_eq(error, false);
    ck_assert_int_eq(req.dest_addr.type, SOCKS_ATYP_IPV6);
    ck_assert_int_eq(req.dest_port, 443);

    struct in6_addr expected;
    inet_pton(AF_INET6, "::1", &expected);
    ck_assert_mem_eq(&req.dest_addr.ipv6, &expected, sizeof(expected));
}
END_TEST

/* ── FQDN ──────────────────────────────────────────────────────────────── */

START_TEST(test_fqdn_connect)
{
    struct socks5_request req;
    struct request_parser p;
    init_parser(&p, &req);
    bool error = false;

    const char *host = "example.com";
    uint8_t hlen = (uint8_t)strlen(host);

    uint8_t msg[4 + 1 + TEST_FQDN_HOST_LEN + 2]; /* header + len_byte + host + port */
    msg[0] = SOCKS_VERSION;
    msg[1] = SOCKS_CMD_CONNECT;
    msg[2] = SOCKS_RSV;
    msg[3] = SOCKS_ATYP_FQDN;
    msg[4] = hlen;
    memcpy(msg + 5, host, hlen);
    msg[5 + hlen] = 0x00;
    msg[5 + hlen + 1] = 0x50; /* port 80 */

    enum request_state st = parse(&p, msg, sizeof(msg), &error);

    ck_assert_int_eq(st, request_done);
    ck_assert_int_eq(error, false);
    ck_assert_int_eq(req.dest_addr.type, SOCKS_ATYP_FQDN);
    ck_assert_str_eq(req.dest_addr.fqdn, "example.com");
    ck_assert_int_eq(req.dest_port, 80);
}
END_TEST

/* ── Error: bad version ────────────────────────────────────────────────── */

START_TEST(test_bad_version)
{
    struct socks5_request req;
    struct request_parser p;
    init_parser(&p, &req);
    bool error = false;

    uint8_t msg[] = {
        0x04 /* VER: wrong version (not 0x05) */
    };
    enum request_state st = parse(&p, msg, sizeof(msg), &error);

    ck_assert_int_eq(st, request_error);
    ck_assert_int_eq(request_is_done(st, NULL), true);
    ck_assert_int_eq(error, true);
}
END_TEST

/* ── Error: BIND rejected ──────────────────────────────────────────────── */

START_TEST(test_bind_rejected)
{
    struct socks5_request req;
    struct request_parser p;
    init_parser(&p, &req);
    bool error = false;

    uint8_t msg[] = {
        SOCKS_VERSION,    /* VER */
        SOCKS_CMD_BIND    /* CMD */
    };
    enum request_state st = parse(&p, msg, sizeof(msg), &error);

    ck_assert_int_eq(st, request_error_unsupported_cmd);
    ck_assert_int_eq(error, false);
    ck_assert_int_eq(request_is_done(st, NULL), true);
}
END_TEST

/* ── Error: UDP ASSOCIATE rejected ────────────────────────────────────── */

START_TEST(test_udp_rejected)
{
    struct socks5_request req;
    struct request_parser p;
    init_parser(&p, &req);
    bool error = false;

    uint8_t msg[] = {
        SOCKS_VERSION,          /* VER */
        SOCKS_CMD_UDP_ASSOCIATE /* CMD */
    };
    enum request_state st = parse(&p, msg, sizeof(msg), &error);

    ck_assert_int_eq(st, request_error_unsupported_cmd);
    ck_assert_int_eq(error, false);
}
END_TEST

/* ── Error: unknown ATYP ──────────────────────────────────────────────── */

START_TEST(test_bad_atyp)
{
    struct socks5_request req;
    struct request_parser p;
    init_parser(&p, &req);
    bool error = false;

    uint8_t msg[] = {
        SOCKS_VERSION,     /* VER */
        SOCKS_CMD_CONNECT, /* CMD */
        SOCKS_RSV,         /* RSV */
        0x02               /* ATYP: undefined value */
    };
    enum request_state st = parse(&p, msg, sizeof(msg), &error);

    ck_assert_int_eq(st, request_error_unsupported_atyp);
    ck_assert_int_eq(error, false);
    ck_assert_int_eq(request_is_done(st, NULL), true);
}
END_TEST

/* ── Error: FQDN with zero-length name ────────────────────────────────── */

START_TEST(test_fqdn_empty_name)
{
    struct socks5_request req;
    struct request_parser p;
    init_parser(&p, &req);
    bool error = false;

    uint8_t msg[] = {
        SOCKS_VERSION,     /* VER */
        SOCKS_CMD_CONNECT, /* CMD */
        SOCKS_RSV,         /* RSV */
        SOCKS_ATYP_FQDN,   /* ATYP */
        0x00               /* LEN: 0 (invalid) */
    };
    enum request_state st = parse(&p, msg, sizeof(msg), &error);

    ck_assert_int_eq(st, request_error);
    ck_assert_int_eq(error, true);
}
END_TEST

/* ── Fragmented input ─────────────────────────────────────────────────── */

START_TEST(test_ipv4_fragmented)
{
    struct socks5_request req;
    struct request_parser p;
    init_parser(&p, &req);

    uint8_t chunk1[] = {
        SOCKS_VERSION,     /* VER */
        SOCKS_CMD_CONNECT, /* CMD */
        SOCKS_RSV,         /* RSV */
        SOCKS_ATYP_IPV4,   /* ATYP */
        10, 0              /* ADDR(2/4): first two bytes of 10.0.0.1 */
    };
    enum request_state st = parse(&p, chunk1, sizeof(chunk1), NULL);
    ck_assert_int_eq(request_is_done(st, NULL), false);

    uint8_t chunk2[] = {
        0, 1,        /* ADDR(4/4): last two bytes → 10.0.0.1 */
        0x1F, 0x90   /* PORT(2): 8080 */
    };
    st = parse(&p, chunk2, sizeof(chunk2), NULL);
    ck_assert_int_eq(st, request_done);
    ck_assert_int_eq(req.dest_port, 8080);
}
END_TEST

/* ── errno_to_socks_reply mapping ─────────────────────────────────────── */

START_TEST(test_errno_mapping)
{
    ck_assert_int_eq(errno_to_socks_reply(ECONNREFUSED), SOCKS_REPLY_CONN_REFUSED);
    ck_assert_int_eq(errno_to_socks_reply(ENETUNREACH),  SOCKS_REPLY_NET_UNREACHABLE);
    ck_assert_int_eq(errno_to_socks_reply(EHOSTUNREACH), SOCKS_REPLY_HOST_UNREACHABLE);
    ck_assert_int_eq(errno_to_socks_reply(ETIMEDOUT),    SOCKS_REPLY_TTL_EXPIRED);
    ck_assert_int_eq(errno_to_socks_reply(ENOENT),       SOCKS_REPLY_GENERAL_FAILURE);
}
END_TEST

/* ── marshall ─────────────────────────────────────────────────────────── */

START_TEST(test_marshall_succeeded)
{
    uint8_t raw[64];
    struct buffer b;
    buffer_init(&b, sizeof(raw), raw);

    ck_assert_int_eq(request_marshall(&b, SOCKS_REPLY_SUCCEEDED), 0);

    size_t avail;
    uint8_t *rp = buffer_read_ptr(&b, &avail);
    ck_assert_uint_eq(avail, 10);
    ck_assert_uint_eq(rp[0], SOCKS_VERSION);
    ck_assert_uint_eq(rp[1], SOCKS_REPLY_SUCCEEDED);
    ck_assert_uint_eq(rp[2], SOCKS_RSV);
    ck_assert_uint_eq(rp[3], SOCKS_ATYP_IPV4);
    ck_assert_uint_eq(rp[4], 0); /* BND.ADDR: 0.0.0.0 */
    ck_assert_uint_eq(rp[5], 0);
    ck_assert_uint_eq(rp[6], 0);
    ck_assert_uint_eq(rp[7], 0);
    ck_assert_uint_eq(rp[8], 0); /* BND.PORT: 0 */
    ck_assert_uint_eq(rp[9], 0);
}
END_TEST

START_TEST(test_marshall_buffer_too_small)
{
    uint8_t raw[9]; /* one byte too small */
    struct buffer b;
    buffer_init(&b, sizeof(raw), raw);
    ck_assert_int_eq(request_marshall(&b, SOCKS_REPLY_SUCCEEDED), -1);
}
END_TEST

/* ── Suite ────────────────────────────────────────────────────────────── */

Suite *
request_suite(void)
{
    Suite *s = suite_create("request");

    TCase *tc_parse = tcase_create("parse");
    tcase_add_test(tc_parse, test_ipv4_connect);
    tcase_add_test(tc_parse, test_ipv6_connect);
    tcase_add_test(tc_parse, test_fqdn_connect);
    tcase_add_test(tc_parse, test_bad_version);
    tcase_add_test(tc_parse, test_bind_rejected);
    tcase_add_test(tc_parse, test_udp_rejected);
    tcase_add_test(tc_parse, test_bad_atyp);
    tcase_add_test(tc_parse, test_fqdn_empty_name);
    tcase_add_test(tc_parse, test_ipv4_fragmented);
    suite_add_tcase(s, tc_parse);

    TCase *tc_netutils = tcase_create("netutils");
    tcase_add_test(tc_netutils, test_errno_mapping);
    suite_add_tcase(s, tc_netutils);

    TCase *tc_marshall = tcase_create("marshall");
    tcase_add_test(tc_marshall, test_marshall_succeeded);
    tcase_add_test(tc_marshall, test_marshall_buffer_too_small);
    suite_add_tcase(s, tc_marshall);

    return s;
}

int
main(void)
{
    SRunner *sr = srunner_create(request_suite());
    srunner_run_all(sr, CK_NORMAL);
    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
