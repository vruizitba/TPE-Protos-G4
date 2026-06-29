#include <stdlib.h>
#include <string.h>
#include <check.h>

#include "auth.c"

static void feed(buffer *b, const uint8_t *bytes, size_t len) {
    size_t available;
    uint8_t *ptr = buffer_write_ptr(b, &available);
    ck_assert_uint_ge(available, len);
    memcpy(ptr, bytes, len);
    buffer_write_adv(b, len);
}

START_TEST (test_auth_full) {
    struct auth_parser parser;
    auth_parser_init(&parser);

    struct buffer buf;
    uint8_t storage[64];
    buffer_init(&buf, sizeof(storage), storage);

    /* VER=1, ULEN=5, "alice", PLEN=6, "secret" */
    uint8_t msg[] = {0x01, 0x05, 'a', 'l', 'i', 'c', 'e',
                     0x06, 's', 'e', 'c', 'r', 'e', 't'};
    feed(&buf, msg, sizeof(msg));

    bool error = false;
    enum auth_state state = auth_consume(&buf, &parser, &error);

    ck_assert(!error);
    ck_assert(auth_is_done(state, NULL));
    ck_assert_str_eq("alice", parser.uname);
    ck_assert_str_eq("secret", parser.passwd);
}
END_TEST

START_TEST (test_auth_fragmented) {
    struct auth_parser parser;
    auth_parser_init(&parser);

    struct buffer buf;
    uint8_t storage[64];
    buffer_init(&buf, sizeof(storage), storage);

    bool error = false;

    uint8_t chunk1[] = {0x01, 0x05, 'a', 'l'};
    feed(&buf, chunk1, sizeof(chunk1));
    enum auth_state state = auth_consume(&buf, &parser, &error);
    ck_assert(!error);
    ck_assert(!auth_is_done(state, NULL));

    uint8_t chunk2[] = {'i', 'c', 'e', 0x03, 'p', 'w', 'd'};
    feed(&buf, chunk2, sizeof(chunk2));
    state = auth_consume(&buf, &parser, &error);
    ck_assert(!error);
    ck_assert(auth_is_done(state, NULL));
    ck_assert_str_eq("alice", parser.uname);
    ck_assert_str_eq("pwd", parser.passwd);
}
END_TEST

START_TEST (test_auth_bad_version) {
    struct auth_parser parser;
    auth_parser_init(&parser);

    struct buffer buf;
    uint8_t storage[16];
    buffer_init(&buf, sizeof(storage), storage);

    uint8_t msg[] = {0x02, 0x01, 'a', 0x01, 'b'};
    feed(&buf, msg, sizeof(msg));

    bool error = false;
    auth_consume(&buf, &parser, &error);
    ck_assert(error);
}
END_TEST

START_TEST (test_auth_zero_ulen) {
    struct auth_parser parser;
    auth_parser_init(&parser);

    struct buffer buf;
    uint8_t storage[16];
    buffer_init(&buf, sizeof(storage), storage);

    uint8_t msg[] = {0x01, 0x00};
    feed(&buf, msg, sizeof(msg));

    bool error = false;
    auth_consume(&buf, &parser, &error);
    ck_assert(error);
}
END_TEST

START_TEST (test_auth_marshall) {
    struct buffer buf;
    uint8_t storage[4];
    buffer_init(&buf, sizeof(storage), storage);

    ck_assert_int_eq(0, auth_marshall(&buf, 0x00));

    size_t pending;
    uint8_t *ptr = buffer_read_ptr(&buf, &pending);
    ck_assert_uint_eq(2, pending);
    ck_assert_uint_eq(0x01, ptr[0]);
    ck_assert_uint_eq(0x00, ptr[1]);
}
END_TEST

Suite *
suite(void) {
    Suite *s = suite_create("auth");
    TCase *tc = tcase_create("auth");

    tcase_add_test(tc, test_auth_full);
    tcase_add_test(tc, test_auth_fragmented);
    tcase_add_test(tc, test_auth_bad_version);
    tcase_add_test(tc, test_auth_zero_ulen);
    tcase_add_test(tc, test_auth_marshall);
    suite_add_tcase(s, tc);

    return s;
}

int
main(void) {
    SRunner *sr = srunner_create(suite());
    int number_failed;

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
