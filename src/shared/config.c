#include <string.h>
#include "config.h"

void
config_init(config_t *c)
{
    memset(c, 0, sizeof(*c));
}
