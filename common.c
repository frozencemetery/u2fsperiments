#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int put(const char *v) {
    fprintf(stdout, "%s\n", v);
    fflush(stdout);
    return 0;
}

char *get() {
    char *buf = calloc(MAX_REPLY_LEN, 1);
    read(0, buf, MAX_REPLY_LEN);
    return buf;
}
