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
    ssize_t len;
    char *buf = calloc(MAX_REPLY_LEN, 1);
    len = read(0, buf, MAX_REPLY_LEN);
    if (len <= 0) {
        free(buf);
        return NULL;
    }

    buf[len - 1] = '\0'; /* clear newline */
    return buf;
}
