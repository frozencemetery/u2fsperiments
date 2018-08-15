/* Copyright (C) 2018 The u2fsperiments contributors */

#include <u2f-host.h>

#include <assert.h>
#include <stdio.h>

int main() {
    u2fh_rc ret;
    u2fh_devs *devs = NULL;
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

    printf("Detected %d device(s)\n", num_devices);

    for (unsigned i = 0; i < num_devices; i++) {
        size_t len = 128;
        char buf[len];
        ret = u2fh_get_device_description(devs, i, buf, &len);
        if (ret)
            goto done;

        buf[len] = '\0';
        printf("%s\n", buf);
    }

    assert(num_devices == 1 && "TODO");

done:
    u2fh_devs_done(devs);
    u2fh_global_done();

    fprintf(stderr, "%s: %s\n", u2fh_strerror_name(ret), u2fh_strerror(ret));
    return ret;
}
