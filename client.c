/* Copyright (C) 2018 The u2fsperiments contributors */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <fido.h>
#include <fido/err.h>

#include "base64.h"
#include "common.h"

/* Why do I even have to specify this.  It's just calling malloc anyway. */
#define MAX_DEVS 64

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

static int chal(fido_dev_t *dev, bool is_reg) {
    fido_cred_t *cred = NULL;
    char *chal_64 = NULL, *cert_64 = NULL, *authdata_64 = NULL,
        *sig_64 = NULL;
    unsigned char *chal_dec = NULL;
    const unsigned char *cert, *authdata, *sig;
    char *reply = NULL;
    size_t len_out;
    int ret = 0;

    chal_64 = get();
    if (!chal_64)
        goto done;

    chal_dec = base64_decode(chal_64, &len_out);
    if (!chal_dec) {
        fprintf(stderr, "base64 challenge decode failed!\n");
        goto done;
    }

    cred = fido_cred_new();
    if (cred == NULL)
        goto done;

    ret = fido_cred_set_type(cred, COSE_ES256);
    if (ret != FIDO_OK)
        goto done;
    
    ret = fido_cred_set_clientdata_hash(cred, chal_dec, len_out);
    if (ret != FIDO_OK)
        goto done;

    ret = fido_cred_set_rp(cred, ORIGIN, ORIGIN);
    if (ret != FIDO_OK)
        goto done;

    fprintf(stderr, "PRESS BLINKY TO DO SOMETHING\n");

    ret = fido_dev_make_cred(dev, cred, NULL);
    if (ret != FIDO_OK)
        goto done;

    authdata = fido_cred_authdata_ptr(cred);
    authdata_64 = base64_encode(authdata, fido_cred_authdata_len(cred));
    if (!authdata_64)
        goto done;

    sig = fido_cred_sig_ptr(cred);
    sig_64 = base64_encode(sig, fido_cred_sig_len(cred));
    if (!sig_64)
        goto done;

    if (is_reg) {
        cert = fido_cred_x5c_ptr(cred);
        cert_64 = base64_encode(cert, fido_cred_x5c_len(cred));
        if (!cert_64)
            goto done;

        ret = asprintf(&reply, "%s %s %s %s\n",
                       fido_cred_fmt(cred), authdata_64, sig_64, cert_64);
    } else {
        ret = asprintf(&reply, "%s %s %s\n",
                       fido_cred_fmt(cred), authdata_64, sig_64);
    }
    if (ret < 0) {
        reply = NULL;
        goto done;
    }

    put(reply);

    ret = 0;
done:
    free(reply);
    free(sig_64);
    free(authdata_64);
    free(cert_64);
    free(chal_64);
    free(chal_dec);
    fido_cred_free(&cred);

    if (ret != FIDO_OK)
        fprintf(stderr, "libfido2: %s\n", fido_strerr(ret));
    return ret;
}

int main() {
    fido_dev_t *dev = NULL;
    int ret = -1;

    dev = setup_u2f();
    if (!dev)
        goto done;

    ret = chal(dev, true);
    if (ret)
        goto done;

    ret = chal(dev, false);

done:
    return ret;
}
