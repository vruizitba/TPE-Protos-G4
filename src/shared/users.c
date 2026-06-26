#include <stddef.h>
#include "users.h"

users_t *
users_create(void)
{
    return NULL;
}

void
users_destroy(users_t *u)
{
    (void)u;
}

bool
users_add(users_t *u, const char *name, const char *pass)
{
    (void)u;
    (void)name;
    (void)pass;
    return false;
}

bool
users_del(users_t *u, const char *name)
{
    (void)u;
    (void)name;
    return false;
}

bool
users_check(users_t *u, const char *name, const char *pass)
{
    (void)u;
    (void)name;
    (void)pass;
    return false;
}

const char *
users_get_name(users_t *u, int i)
{
    (void)u;
    (void)i;
    return NULL;
}
