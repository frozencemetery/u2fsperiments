/* Copyright (C) 2018 The u2fsperiments contributors */

#include <curl/curl.h>

#include <u2f-host.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define USERNAME "rharwood"
#define PASSWORD "secretes"
#define ORIGIN "https://demo.yubico.com"
#define ENDPOINT "%s/wsapi/u2f/enroll?username=%s&password=%s"

/* The library makes no guarantees about this, but this is what libu2f used
 * internally when I looked. */
#define MAX_REPLY_LEN 2048

typedef struct {
    size_t len;
    char *data;
} buffer;

size_t write_callback(char *data, size_t size, size_t nmemb, void *userdata) {
    buffer *buf = userdata;
    size_t bytes = size * nmemb;
    char *tmp;

    tmp = realloc(buf->data, buf->len + bytes + 1);
    if (!tmp) {
        free(buf->data);
        buf->data = NULL;
        buf->len = 0;
        return 0;
    }
    buf->data = tmp;

    memcpy(buf->data + buf->len, data, bytes);
    buf->len += bytes;
    buf->data[buf->len] = '\0';
    return bytes;
}

CURL *setup_curl(buffer *buf) {
    CURLcode ret;
    CURL *curl;

    ret = curl_global_init(CURL_GLOBAL_DEFAULT);
    if (ret)
        goto done;

    curl = curl_easy_init();
    if (!curl)
        goto done;

    ret = curl_easy_setopt(curl, CURLOPT_WRITEDATA, buf);
    if (ret)
        goto done;

    ret = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    if (ret)
        goto done;

    return curl;

done:
    curl_easy_cleanup(curl);
    return NULL;
}

char *get_register_challenge(CURL *curl, buffer *buf, const char *username,
                             const char *password) {
    int aret;
    CURLcode ret;
    char *out = NULL, *url = NULL;

    aret = asprintf(&url, ENDPOINT, ORIGIN, username, password);
    if (aret == -1) {
        url = NULL;
        goto done;
    }

    ret = curl_easy_setopt(curl, CURLOPT_URL, url);
    if (ret)
        goto done;

    ret = curl_easy_perform(curl);
    if (ret || !buf->data)
        goto done;

    out = buf->data;
    buf->data = NULL;

done:
    free(buf->data);
    buf->data = NULL;
    buf->len = 0;
    free(url);
    return out;
}

int main() {
    CURL *curl = NULL;
    buffer buf = { 0 };
    u2fh_rc ret;
    u2fh_devs *devs = NULL;
    unsigned num_devices;
    char *challenge = NULL, response[MAX_REPLY_LEN];
    size_t response_len = MAX_REPLY_LEN;

    curl = setup_curl(&buf);
    if (!curl)
        goto done;

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

    challenge = get_register_challenge(curl, &buf, USERNAME, PASSWORD);
    if (!challenge) {
        fprintf(stderr, "No challenge found!\n");
        goto done;
    }

    printf("PUSH BLINKY TO REGISTER\n");

    ret = u2fh_register2(devs, challenge, ORIGIN, response, &response_len,
                         U2FH_REQUEST_USER_PRESENCE);
    if (ret)
        goto done;

    printf("%s\n", response);

done:
    free(challenge);
    u2fh_devs_done(devs);
    u2fh_global_done();
    curl_easy_cleanup(curl);

    fprintf(stderr, "%s: %s\n", u2fh_strerror_name(ret), u2fh_strerror(ret));
    return ret;
}
