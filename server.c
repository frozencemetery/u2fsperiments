/* Copyright (C) 2018 The u2fsperiments contributors */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/random.h>

#include <fido.h>

#include "base64.h"
#include "common.h"

static int send_challenge(fido_cred_t *cred) {
    char raw[CHALLENGE_LEN + 1], *encoded;
    ssize_t gret;
    int fret;

    fprintf(stderr, "Generating challenge...\n");

    gret = getrandom(raw, CHALLENGE_LEN, 0);
    if (gret != CHALLENGE_LEN)
        return -1;
    raw[CHALLENGE_LEN] = '\0';

    fret = fido_cred_set_clientdata_hash(cred, (unsigned char *)raw,
                                         CHALLENGE_LEN);
    if (fret != FIDO_OK) {
        fprintf(stderr, "libfido2: %s\n", fido_strerr(fret));
        return -1;
    }

    encoded = base64_encode(raw, CHALLENGE_LEN);
    if (!encoded)
        return -1;

    encoded[B64U_LEN] = '\0';

    put(encoded);
    free(encoded);
    return 0;
}

static int verify_reg(fido_cred_t *cred) {
    char *blob = NULL;
    char *fmt, *cert_64, *authdata_64, *sig_64;
    unsigned char *cert = NULL, *authdata = NULL, *sig = NULL;
    size_t cert_len, authdata_len, sig_len;
    int ret = -1;

    blob = get();
    if (blob == NULL)
        goto done;

    fmt = blob;

    blob = strchr(blob, ' ');
    if (blob == NULL)
        goto done;
    *blob++ = '\0';
    cert_64 = blob;

    blob = strchr(blob, ' ');
    if (blob == NULL)
        goto done;
    *blob++ = '\0';
    authdata_64 = blob;

    blob = strchr(blob, ' ');
    if (blob == NULL)
        goto done;
    *blob++ = '\0';
    sig_64 = blob;

    cert = base64_decode(cert_64, &cert_len);
    authdata = base64_decode(authdata_64, &authdata_len);
    sig = base64_decode(sig_64, &sig_len);
    if (cert == NULL || authdata == NULL || sig == NULL)
        goto done;

    ret = fido_cred_set_fmt(cred, fmt);
    if (ret != FIDO_OK)
        goto done;

    ret = fido_cred_set_x509(cred, cert, cert_len);
    if (ret != FIDO_OK)
        goto done;

    ret = fido_cred_set_authdata(cred, authdata, authdata_len);
    if (ret != FIDO_OK)
        goto done;

    ret = fido_cred_set_sig(cred, sig, sig_len);
    if (ret != FIDO_OK)
        goto done;

    fprintf(stderr, "%s %s %s %s\n", fido_cred_fmt(cred), cert_64,
            authdata_64, sig_64);

    ret = fido_cred_verify(cred);
    if (ret != FIDO_OK)
        goto done;

    fprintf(stderr, "CRED VERIFIED EVERYBODY PARTY\n");

done:
    if (ret != FIDO_OK)
        fprintf(stderr, "libfido2: %s\n", fido_strerr(ret));

    free(cert);
    free(authdata);
    free(sig);
    free(fmt);
    return ret;
}

int main() {
    int ret;
    fido_cred_t *cred = NULL;

    fido_init(0);

    cred = fido_cred_new();
    if (cred == NULL)
        goto done;

    ret = fido_cred_set_rp(cred, ORIGIN, ORIGIN);
    if (ret != FIDO_OK)
        goto done;

    ret = fido_cred_set_type(cred, COSE_ES256);
    if (ret != FIDO_OK)
        goto done;

    ret = send_challenge(cred);
    if (ret != 0)
        goto done;

    ret = verify_reg(cred);
    if (ret != 0)
        goto done;

    ret = 0;
done:
    fido_cred_free(&cred);
    return ret;
}
