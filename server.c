/* Copyright (C) 2018 The u2fsperiments contributors */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/random.h>

#include <u2f-server/u2f-server.h>

#include "base64.h"
#include "common.h"

/* copied from libu2f-server */
#define RAW_LEN 32
#define B64U_LEN 43

u2fs_rc update_challenge(u2fs_ctx_t *ctx) {
    char raw[RAW_LEN], *encoded;
    ssize_t gret;
    u2fs_rc ret = 0;

    fprintf(stderr, "Generating challenge...\n");

    gret = getrandom(raw, RAW_LEN, 0);
    if (gret != RAW_LEN)
        return -1;

    encoded = base64_encode(raw, RAW_LEN);
    if (!encoded)
        return -1;
    encoded[B64U_LEN] = '\0';

    ret = u2fs_set_challenge(ctx, encoded);
    free(encoded);
    return ret;
}

u2fs_rc sign_loop(u2fs_ctx_t *ctx) {
    u2fs_rc ret, verified;
    uint32_t counter;
    uint8_t user_presence;
    char *challenge = NULL, *buf = NULL;
    u2fs_auth_res_t *auth_res;

    while (1) {
        ret = update_challenge(ctx);
        if (ret)
            goto done;

        ret = u2fs_authentication_challenge(ctx, &challenge);
        if (ret)
            goto done;

        put(challenge);

        buf = get();
        if (!buf || strlen(buf) <= 1) {
            fprintf(stderr, "No signed blob!\n");
            free(challenge);
            free(buf);
            return ret;
        }

        fprintf(stderr, "Got signed blob!\n");

        ret = u2fs_authentication_verify(ctx, buf, &auth_res);
        if (ret)
            goto done;

        fprintf(stderr, "verified!\n");

        ret = u2fs_get_authentication_result(auth_res, &verified, &counter,
                                             &user_presence);
        if (ret)
            goto done;

        fprintf(stderr, "%s, %d touches, %s\n",
                verified ? "verified" : "unverified", counter,
                user_presence ? "present" : "absent");

    done:
        free(buf);
        buf = NULL;
        free(challenge);
        challenge = NULL;
        u2fs_free_auth_res(auth_res);
        auth_res = NULL;
        if (ret)
            return ret;
    }
}

int main() {
    u2fs_rc ret;
    u2fs_ctx_t *ctx;
    char *challenge = NULL, *buf = NULL;
    const char *keyhandle, * publickey;
    u2fs_reg_res_t *result = NULL;

    ret = u2fs_global_init(0);
    if (ret)
        goto done;

    ret = u2fs_init(&ctx);
    if (ret)
        goto done;

    ret = u2fs_set_appid(ctx, "u2fsperiments");
    if (ret)
        goto done;

    ret = u2fs_set_origin(ctx, ORIGIN);
    if (ret)
        goto done;

    ret = update_challenge(ctx);
    if (ret)
        goto done;

    ret = u2fs_registration_challenge(ctx, &challenge);
    if (ret)
        goto done;

    put(challenge);

    buf = get();

    ret = u2fs_registration_verify(ctx, buf, &result);
    if (ret)
        goto done;

    keyhandle = u2fs_get_registration_keyHandle(result);
    publickey = u2fs_get_registration_publicKey(result);

    fprintf(stderr, "Token registered (for this server session)\n");

    free(challenge);
    challenge = NULL;

    ret = u2fs_set_keyHandle(ctx, keyhandle);
    if (ret)
        goto done;

    fprintf(stderr, "Set keyhandle\n");

    ret = u2fs_set_publicKey(ctx, (const unsigned char *)publickey);
    if (ret)
        goto done;

    fprintf(stderr, "Set pubkey\n");

    ret = sign_loop(ctx);

done:
    if (ret)
        fprintf(stderr, "problem: %s\n", u2fs_strerror(ret));

    u2fs_free_reg_res(result);
    free(buf);
    free(challenge);
    u2fs_done(ctx);
    u2fs_global_done();
    return ret;
}
