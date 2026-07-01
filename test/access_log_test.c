#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <check.h>

#include "access_log.c"

#define TMP_PATH "/tmp/access_log_test.tmp"

static char *read_first_line(const char *path, char *out, size_t out_len) {
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        return NULL;
    }
    char *line = fgets(out, (int)out_len, f);
    fclose(f);
    return line;
}

static int count_fields(const char *line, char fields[][128], int max_fields) {
    int count = 0;
    const char *start = line;
    for (const char *p = line; *p != '\0' && count < max_fields; p++) {
        if (*p == '\t' || *p == '\n') {
            size_t len = (size_t)(p - start);
            if (len >= 128) {
                len = 127;
            }
            memcpy(fields[count], start, len);
            fields[count][len] = '\0';
            count++;
            start = p + 1;
        }
    }
    return count;
}

START_TEST (test_log_open_format) {
    remove(TMP_PATH);
    access_log_t *log = access_log_create(TMP_PATH);
    ck_assert_ptr_nonnull(log);

    access_log_open(log, "alice", "example.com", 80);
    access_log_destroy(log);

    char line[512];
    ck_assert_ptr_nonnull(read_first_line(TMP_PATH, line, sizeof(line)));

    char fields[8][128];
    int n = count_fields(line, fields, 8);
    ck_assert_int_eq(6, n);
    ck_assert_str_eq("alice", fields[1]);
    ck_assert_str_eq("example.com:80", fields[2]);
    ck_assert_str_eq("-", fields[3]);
    ck_assert_str_eq("-", fields[4]);
    ck_assert_str_eq("OPEN", fields[5]);

    remove(TMP_PATH);
}
END_TEST

START_TEST (test_log_close_format) {
    remove(TMP_PATH);
    access_log_t *log = access_log_create(TMP_PATH);
    ck_assert_ptr_nonnull(log);

    access_log_close(log, "bob", "1.2.3.4", 443, 100, 200);
    access_log_destroy(log);

    char line[512];
    ck_assert_ptr_nonnull(read_first_line(TMP_PATH, line, sizeof(line)));

    char fields[8][128];
    int n = count_fields(line, fields, 8);
    ck_assert_int_eq(6, n);
    ck_assert_str_eq("bob", fields[1]);
    ck_assert_str_eq("1.2.3.4:443", fields[2]);
    ck_assert_str_eq("100", fields[3]);
    ck_assert_str_eq("200", fields[4]);
    ck_assert_str_eq("CLOSE", fields[5]);

    remove(TMP_PATH);
}
END_TEST

START_TEST (test_log_null_user) {
    remove(TMP_PATH);
    access_log_t *log = access_log_create(TMP_PATH);
    ck_assert_ptr_nonnull(log);

    access_log_open(log, NULL, "host", 1080);
    access_log_destroy(log);

    char line[512];
    ck_assert_ptr_nonnull(read_first_line(TMP_PATH, line, sizeof(line)));

    char fields[8][128];
    count_fields(line, fields, 8);
    ck_assert_str_eq("-", fields[1]);

    remove(TMP_PATH);
}
END_TEST

Suite *
suite(void) {
    Suite *s = suite_create("access_log");
    TCase *tc = tcase_create("access_log");

    tcase_add_test(tc, test_log_open_format);
    tcase_add_test(tc, test_log_close_format);
    tcase_add_test(tc, test_log_null_user);
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
