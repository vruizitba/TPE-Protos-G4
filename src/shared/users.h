#ifndef USERS_H
#define USERS_H

#include <stdbool.h>

#define USERS_MAX 10

typedef struct users users_t;

users_t *users_create(void);
void users_destroy(users_t *u);

bool users_add(users_t *u, const char *name, const char *pass);
bool users_del(users_t *u, const char *name);
bool users_check(users_t *u, const char *name, const char *pass);

/* Iterate: returns name of user at index i, NULL if out of bounds */
const char *users_get_name(users_t *u, int i);

#endif
