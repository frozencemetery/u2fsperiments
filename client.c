/* Copyright (C) 2018 The u2fsperiments contributors */

#include <stdio.h>
#include <stdlib.h>

#include <fido.h>
#include <fido/err.h>

#include "common.h"

/* Why do I even have to specify this.  It's just calling malloc anyway. */
#define MAX_DEVS 64

static const unsigned char challenge[32] = {
    0xf9, 0x64, 0x57, 0xe7, 0x2d, 0x97, 0xf6, 0xbb,
    0xdd, 0xd7, 0xfb, 0x06, 0x37, 0x62, 0xea, 0x26,
    0x20, 0x44, 0x8e, 0x69, 0x7c, 0x03, 0xf2, 0x31,
    0x2f, 0x99, 0xdc, 0xaf, 0x3e, 0x8a, 0x91, 0x6b,
};

static fido_dev_t *setup_u2f() {
    fido_dev_info_t *devlist = NULL;
    size_t num_devices = 0;
    fido_dev_t *dev = NULL;
    const char *path;
    int ret = 0;
    
    fido_init(0);

    devlist = fido_dev_info_new(MAX_DEVS);
    if (!devlist)
        goto done;

    ret = fido_dev_info_manifest(devlist, MAX_DEVS, &num_devices);
    if (ret != FIDO_OK || num_devices == 0) {
        fprintf(stderr, "No U2F devices found!\n");
        goto done;
    }
    fprintf(stderr, "Detected %ld device(s)\n", num_devices);

    for (size_t i = 0; i < num_devices; i++) {
        const fido_dev_info_t *di = fido_dev_info_ptr(devlist, i);
        path = fido_dev_info_path(di);
        fprintf(stderr, "Device %ld - %s; %ls; %ls\n", i, path,
                fido_dev_info_manufacturer_string(di),
                fido_dev_info_product_string(di));
    }
    if (num_devices > 1) {
        fprintf(stderr, "More than one device found; I can't cope\n");
        goto done;
    }

    dev = fido_dev_new();
    if (dev == NULL)
        goto done;

    ret = fido_dev_open(dev, path);
    if (ret != FIDO_OK) {
        fido_dev_close(dev);
        fido_dev_free(&dev);
    }

done:
    if (ret != FIDO_OK)
        fprintf(stderr, "libfido2: %s\n", fido_strerr(ret));
    fido_dev_info_free(&devlist, num_devices);
    return dev;
}

static int chal(fido_dev_t *dev) {
    fido_cred_t *cred = NULL;
    int ret = 0;

    cred = fido_cred_new();
    if (cred == NULL)
        goto done;

    ret = fido_cred_set_type(cred, COSE_ES256);
    if (ret != FIDO_OK)
        goto done;
    
    ret = fido_cred_set_clientdata_hash(cred, challenge, sizeof(challenge));
    if (ret != FIDO_OK)
        goto done;

    ret = fido_cred_set_rp(cred, ORIGIN, ORIGIN);
    if (ret != FIDO_OK)
        goto done;

    fprintf(stderr, "PRESS BLINKY TO DO SOMETHING\n");

    ret = fido_dev_make_cred(dev, cred, NULL);
    if (ret != FIDO_OK)
        goto done;

done:
    if (ret != FIDO_OK)
        fprintf(stderr, "libfido2: %s\n", fido_strerr(ret));
    fido_cred_free(&cred);
    return ret;
}

int main() {
    fido_dev_t *dev = NULL;
    int ret = -1;

    dev = setup_u2f();
    if (!dev)
        goto done;

    ret = chal(dev);
    if (ret)
        goto done;

    ret = 0;
done:
    return ret;
}
