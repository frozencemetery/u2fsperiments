/* Copyright (C) 2018 The u2fsperiments contributors */

#include <stdio.h>
#include <stdlib.h>

#include <u2f-host.h>

#include "common.h"

u2fh_devs *setup_u2f() {
    u2fh_devs *devs = NULL;
    u2fh_rc ret;
    unsigned num_devices;

    ret = u2fh_global_init(0); /* not enabling debug */
    if (ret)
        goto done;

    ret = u2fh_devs_init(&devs);
    if (ret)
        goto done;

    /* this interface is bad */
    ret = u2fh_devs_discover(devs, &num_devices);
    num_devices++;
    if (ret == U2FH_NO_U2F_DEVICE) {
        fprintf(stderr, "No U2F devices found!\n");
        ret = 0;
        goto done;
    } else if (ret)
        goto done;

    fprintf(stderr, "Detected %d device(s)\n", num_devices);

    for (unsigned i = 0; i < num_devices; i++) {
        size_t len = 78;
        char buf[len];
        ret = u2fh_get_device_description(devs, i, buf, &len);
        if (ret)
            goto done;

        buf[len] = '\0';
        fprintf(stderr, "Device %d: %s\n", i, buf);
    }

    return devs;

done:
    u2fh_devs_done(devs);
    fprintf(stderr, "%s: %s\n", u2fh_strerror_name(ret), u2fh_strerror(ret));
    return NULL;
}

static u2fh_rc sign_loop(u2fh_devs *devs) {
    u2fh_rc ret;
    char *challenge = NULL;
    char response[MAX_REPLY_LEN];
    size_t response_len = MAX_REPLY_LEN;

    while (1) {
        challenge = get();
        if (!challenge || strlen(challenge) <= 1) {
            printf("NO CHALLENGE\n");
            free(challenge);
            return 0;
        }

        fprintf(stderr, "PUSH BLINKY TO SIGN\n");

        response_len = MAX_REPLY_LEN;
        memset(response, 0, response_len);
        ret = u2fh_authenticate2(devs, challenge, ORIGIN, response,
                                 &response_len, U2FH_REQUEST_USER_PRESENCE);
        free(challenge);
        if (ret)
            return ret;

        response[response_len] = '\0';

        put(response);
    }
}

static u2fh_rc register_device(u2fh_devs *devs) {
    u2fh_rc ret = 0;
    char *challenge = NULL;
    char response[MAX_REPLY_LEN];
    size_t response_len = MAX_REPLY_LEN;
    
    challenge = get();

    fprintf(stderr, "PUSH BLINKY TO REGISTER\n");

    ret = u2fh_register2(devs, challenge, ORIGIN, response, &response_len,
                         U2FH_REQUEST_USER_PRESENCE);
    if (ret)
        goto done;
    response[response_len] = '\0';

    put(response);

done:
    free(challenge);
    return ret;
}

int main() {
    u2fh_rc ret;
    u2fh_devs *devs = NULL;

    devs = setup_u2f();
    if (!devs)
        goto done;

    ret = register_device(devs);
    if (ret)
        goto done;

    ret = sign_loop(devs);

done:
    u2fh_devs_done(devs);
    u2fh_global_done();

    return ret;
}
