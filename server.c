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

/* Registration expects a cert to be supplied in the datastream. */
static int verify(fido_cred_t *cred, unsigned char **cert_out,
                  size_t *cert_len_out) {
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
    authdata_64 = blob;

    blob = strchr(blob, ' ');
    if (blob == NULL)
        goto done;
    *blob++ = '\0';
    sig_64 = blob;

    if (cert_out != NULL) {
        blob = strchr(blob, ' ');
        if (blob == NULL)
            goto done;
        *blob++ = '\0';
        cert_64 = blob;

        cert = base64_decode(cert_64, &cert_len);
        if (cert == NULL)
            goto done;
    }

    authdata = base64_decode(authdata_64, &authdata_len);
    sig = base64_decode(sig_64, &sig_len);
    if (authdata == NULL || sig == NULL)
        goto done;

    ret = fido_cred_set_fmt(cred, fmt);
    if (ret != FIDO_OK)
        goto done;

    if (cert_out != NULL) {
        ret = fido_cred_set_x509(cred, cert, cert_len);
        if (ret != FIDO_OK)
            goto done;
    }

    ret = fido_cred_set_authdata(cred, authdata, authdata_len);
    if (ret != FIDO_OK)
        goto done;

    ret = fido_cred_set_sig(cred, sig, sig_len);
    if (ret != FIDO_OK)
        goto done;

    ret = fido_cred_verify(cred);
    if (ret != FIDO_OK)
        goto done;

    fprintf(stderr, "REGISTRATION COMPLETE (and verified)\n");

    if (cert_out != NULL) {
        *cert_len_out = cert_len;
        *cert_out = malloc(cert_len);
        if (*cert_out != NULL)
            memcpy(*cert_out, cert, cert_len);
        cert = NULL;
    }

done:
    if (ret != FIDO_OK)
        fprintf(stderr, "libfido2: %s\n", fido_strerr(ret));

    free(cert);
    free(authdata);
    free(sig);
    free(fmt);
    return ret;
}

static int verify_reg(fido_cred_t *cred, unsigned char **cert_out,
                      size_t *cert_len_out) {
    return verify(cred, cert_out, cert_len_out);
}

static int verify_sig(fido_cred_t *cred) {
    return verify(cred, NULL, NULL);
}

static fido_cred_t *new_cred() {
    fido_cred_t *cred;
    int ret;

    cred = fido_cred_new();
    if (cred == NULL)
        goto done;

    ret = fido_cred_set_rp(cred, ORIGIN, ORIGIN);
    if (ret != FIDO_OK)
        goto done;

    ret = fido_cred_set_type(cred, COSE_ES256);

done:
    if (ret != FIDO_OK)
        fido_cred_free(&cred);
    return cred;
}

int main() {
    int ret;
    fido_cred_t *cred = NULL;
    unsigned char *cert = NULL;
    size_t cert_len;

    fido_init(0);

    cred = new_cred();
    if (cred == NULL)
        goto done;

    ret = send_challenge(cred);
    if (ret != 0)
        goto done;

    ret = verify_reg(cred, &cert, &cert_len);
    if (ret != 0 || cert == NULL)
        goto done;

    fido_cred_free(&cred);
    cred = new_cred();
    if (cred == NULL)
        goto done;

    ret = send_challenge(cred);
    if (ret != 0)
        goto done;

    ret = fido_cred_set_x509(cred, cert, cert_len);
    if (ret != FIDO_OK)
        goto done;

    ret = verify_sig(cred);
    if (ret != 0)
        goto done;

    ret = 0;
done:
    free(cert);
    fido_cred_free(&cred);
    return ret;
}
