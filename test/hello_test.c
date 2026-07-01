#include <stdlib.h>
#include <string.h>
#include <check.h>

#include "hello.c"

static uint8_t recorded_methods[16];
static int recorded_count;

static void record_method(struct hello_parser *parser, uint8_t method) {
    (void)parser;
    if (recorded_count < 16) {
        recorded_methods[recorded_count++] = method;
    }
}

static void feed(buffer *b, const uint8_t *bytes, size_t len) {
    size_t available;
    uint8_t *ptr = buffer_write_ptr(b, &available);
    ck_assert_uint_ge(available, len);
    memcpy(ptr, bytes, len);
    buffer_write_adv(b, len);
}

START_TEST (test_hello_full) {
    recorded_count = 0;
    struct hello_parser parser;
    parser.on_authentication_method = record_method;
    parser.data = NULL;
    hello_parser_init(&parser);

    struct buffer buf;
    uint8_t storage[32];
    buffer_init(&buf, sizeof(storage), storage);

    /* VER=5, NMETHODS=2, METHODS={0x00, 0x02} */
    uint8_t msg[] = {0x05, 0x02, 0x00, 0x02};
    feed(&buf, msg, sizeof(msg));

    bool error = false;
    enum hello_state state = hello_consume(&buf, &parser, &error);

    ck_assert(!error);
    ck_assert(hello_is_done(state, NULL));
    ck_assert_int_eq(2, recorded_count);
    ck_assert_uint_eq(0x00, recorded_methods[0]);
    ck_assert_uint_eq(0x02, recorded_methods[1]);
}
END_TEST

START_TEST (test_hello_fragmented) {
    recorded_count = 0;
    struct hello_parser parser;
    parser.on_authentication_method = record_method;
    parser.data = NULL;
    hello_parser_init(&parser);

    struct buffer buf;
    uint8_t storage[32];
    buffer_init(&buf, sizeof(storage), storage);

    bool error = false;

    /* first chunk: VER, NMETHODS */
    uint8_t chunk1[] = {0x05, 0x02};
    feed(&buf, chunk1, sizeof(chunk1));
    enum hello_state state = hello_consume(&buf, &parser, &error);
    ck_assert(!error);
    ck_assert(!hello_is_done(state, NULL));

    /* second chunk: the two methods */
    uint8_t chunk2[] = {0x00, 0x02};
    feed(&buf, chunk2, sizeof(chunk2));
    state = hello_consume(&buf, &parser, &error);
    ck_assert(!error);
    ck_assert(hello_is_done(state, NULL));
    ck_assert_int_eq(2, recorded_count);
}
END_TEST

START_TEST (test_hello_bad_version) {
    struct hello_parser parser;
    parser.on_authentication_method = record_method;
    parser.data = NULL;
    hello_parser_init(&parser);

    struct buffer buf;
    uint8_t storage[32];
    buffer_init(&buf, sizeof(storage), storage);

    uint8_t msg[] = {0x04, 0x01, 0x00};
    feed(&buf, msg, sizeof(msg));

    bool error = false;
    hello_consume(&buf, &parser, &error);
    ck_assert(error);
}
END_TEST

START_TEST (test_hello_zero_methods) {
    struct hello_parser parser;
    parser.on_authentication_method = record_method;
    parser.data = NULL;
    hello_parser_init(&parser);

    struct buffer buf;
    uint8_t storage[32];
    buffer_init(&buf, sizeof(storage), storage);

    uint8_t msg[] = {0x05, 0x00};
    feed(&buf, msg, sizeof(msg));

    bool error = false;
    hello_consume(&buf, &parser, &error);
    ck_assert(error);
}
END_TEST

START_TEST (test_hello_marshall) {
    struct buffer buf;
    uint8_t storage[4];
    buffer_init(&buf, sizeof(storage), storage);

    ck_assert_int_eq(0, hello_marshall(&buf, 0x02));

    size_t pending;
    uint8_t *ptr = buffer_read_ptr(&buf, &pending);
    ck_assert_uint_eq(2, pending);
    ck_assert_uint_eq(0x05, ptr[0]);
    ck_assert_uint_eq(0x02, ptr[1]);
}
END_TEST

Suite *
suite(void) {
    Suite *s = suite_create("hello");
    TCase *tc = tcase_create("hello");

    tcase_add_test(tc, test_hello_full);
    tcase_add_test(tc, test_hello_fragmented);
    tcase_add_test(tc, test_hello_bad_version);
    tcase_add_test(tc, test_hello_zero_methods);
    tcase_add_test(tc, test_hello_marshall);
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
