/* Copyright (C) 2018 The u2fsperiments contributors */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/random.h>

#include "base64.h"
#include "common.h"

int send_challenge() {
    char raw[CHALLENGE_LEN], *encoded;
    ssize_t gret;

    fprintf(stderr, "Generating challenge...\n");

    gret = getrandom(raw, CHALLENGE_LEN, 0);
    if (gret != CHALLENGE_LEN)
        return -1;

    encoded = base64_encode(raw, CHALLENGE_LEN);
    if (!encoded)
        return -1;

    encoded[B64U_LEN] = '\0';

    put(encoded);
    free(encoded);
    return 0;
}


int main() {
    int ret = -1;

    send_challenge();

    ret = 0;
done:
    return ret;
}
