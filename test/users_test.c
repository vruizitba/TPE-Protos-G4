#include <stdlib.h>
#include <stdio.h>
#include <check.h>

#include "users.c"

START_TEST (test_users_add_and_check) {
    users_t *users = users_create();
    ck_assert_ptr_nonnull(users);
    ck_assert_int_eq(0, users_count(users));

    ck_assert(users_add(users, "alice", "secret"));
    ck_assert_int_eq(1, users_count(users));

    ck_assert(users_check(users, "alice", "secret"));
    ck_assert(!users_check(users, "alice", "wrong"));
    ck_assert(!users_check(users, "bob", "secret"));

    users_destroy(users);
}
END_TEST

START_TEST (test_users_upsert) {
    users_t *users = users_create();

    ck_assert(users_add(users, "alice", "old"));
    ck_assert(users_add(users, "alice", "new"));
    ck_assert_int_eq(1, users_count(users));

    ck_assert(!users_check(users, "alice", "old"));
    ck_assert(users_check(users, "alice", "new"));

    users_destroy(users);
}
END_TEST

START_TEST (test_users_full) {
    users_t *users = users_create();

    char name[32];
    for (int i = 0; i < USERS_MAX; i++) {
        snprintf(name, sizeof(name), "user%d", i);
        ck_assert(users_add(users, name, "pass"));
    }
    ck_assert_int_eq(USERS_MAX, users_count(users));

    ck_assert(!users_add(users, "overflow", "pass"));
    ck_assert_int_eq(USERS_MAX, users_count(users));

    users_destroy(users);
}
END_TEST

START_TEST (test_users_del) {
    users_t *users = users_create();

    ck_assert(users_add(users, "alice", "a"));
    ck_assert(users_add(users, "bob", "b"));
    ck_assert_int_eq(2, users_count(users));

    ck_assert(users_del(users, "alice"));
    ck_assert_int_eq(1, users_count(users));
    ck_assert(!users_check(users, "alice", "a"));
    ck_assert(users_check(users, "bob", "b"));

    ck_assert(!users_del(users, "alice"));

    users_destroy(users);
}
END_TEST

START_TEST (test_users_get_name) {
    users_t *users = users_create();

    ck_assert_ptr_null(users_get_name(users, 0));
    ck_assert(users_add(users, "alice", "a"));
    ck_assert_str_eq("alice", users_get_name(users, 0));
    ck_assert_ptr_null(users_get_name(users, 1));
    ck_assert_ptr_null(users_get_name(users, -1));

    users_destroy(users);
}
END_TEST

Suite *
suite(void) {
    Suite *s = suite_create("users");
    TCase *tc = tcase_create("users");

    tcase_add_test(tc, test_users_add_and_check);
    tcase_add_test(tc, test_users_upsert);
    tcase_add_test(tc, test_users_full);
    tcase_add_test(tc, test_users_del);
    tcase_add_test(tc, test_users_get_name);
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
