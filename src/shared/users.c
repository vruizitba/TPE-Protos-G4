#include <stdlib.h>
#include <string.h>
#include "users.h"

#define NAME_LEN 256
#define PASS_LEN 256

typedef struct {
    char name[NAME_LEN];
    char pass[PASS_LEN];
} user_entry_t;

struct users {
    user_entry_t entries[USERS_MAX];
    int count;
};

users_t *users_create(void) {
    users_t *u = calloc(1, sizeof(*u));
    return u;
}

void users_destroy(users_t *u) {
    free(u);
}

static int find_user(users_t *u, const char *name) {
    for (int i = 0; i < u->count; i++) {
        if (strncmp(u->entries[i].name, name, NAME_LEN) == 0) {
            return i;
        }
    }
    return -1;
}

bool users_add(users_t *u, const char *name, const char *pass) {
    int idx = find_user(u, name);
    if (idx >= 0) {
        strncpy(u->entries[idx].pass, pass, PASS_LEN - 1);
        u->entries[idx].pass[PASS_LEN - 1] = '\0';
        return true;
    }
    if (u->count >= USERS_MAX) {
        return false;
    }
    strncpy(u->entries[u->count].name, name, NAME_LEN - 1);
    u->entries[u->count].name[NAME_LEN - 1] = '\0';
    strncpy(u->entries[u->count].pass, pass, PASS_LEN - 1);
    u->entries[u->count].pass[PASS_LEN - 1] = '\0';
    u->count++;
    return true;
}

bool users_del(users_t *u, const char *name) {
    int idx = find_user(u, name);
    if (idx < 0) {
        return false;
    }
    u->entries[idx] = u->entries[u->count - 1];
    memset(&u->entries[u->count - 1], 0, sizeof(user_entry_t));
    u->count--;
    return true;
}

bool users_check(users_t *u, const char *name, const char *pass) {
    int idx = find_user(u, name);
    if (idx < 0) {
        return false;
    }
    return strncmp(u->entries[idx].pass, pass, PASS_LEN) == 0;
}

const char *users_get_name(users_t *u, int i) {
    if (i < 0 || i >= u->count) {
        return NULL;
    }
    return u->entries[i].name;
}
