#pragma once

#include <err.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>

struct config {
    char *port;
    int sock;
};
