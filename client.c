/* Copyright (C) 2018 The u2fsperiments contributors */

#include <curl/curl.h>

#include <u2f-host.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define USERNAME "rharwood"
#define PASSWORD "secretes"
#define ENDPOINT "https://demo.yubico.com/wsapi/u2f/enroll?username=%s&password=%s"

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

char *get_register_challenge(const char *username, const char *password) {
    int aret;
    CURLcode ret;
    CURL *curl;
    char *out = NULL, *url = NULL, *p, *n, *end;
    buffer response = { 0 };

    ret = curl_global_init(CURL_GLOBAL_DEFAULT);
    if (ret)
        goto done;

    curl = curl_easy_init();
    if (!curl)
        goto done;

    ret = curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    if (ret)
        goto done;

    ret = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    if (ret)
        goto done;

    aret = asprintf(&url, ENDPOINT, username, password);
    if (aret == -1) {
        url = NULL;
        goto done;
    }

    ret = curl_easy_setopt(curl, CURLOPT_URL, url);
    if (ret)
        goto done;

    ret = curl_easy_perform(curl);
    if (ret || !response.data)
        goto done;

    printf("%s\n", response.data);

    n = "\"challenge\"";
    p = strstr(response.data, n);
    if (!p)
        goto done;

    p += strlen(n);
    while (*p == ':' || *p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' ||
           *p == '\v' || *p == '"')
        p++;

    end = strchr(p, '"');
    if (!end)
        goto done;
    *end = '\0';

    out = strdup(p);
done:
    free(response.data);
    free(url);
    curl_easy_cleanup(curl);
    return out;
}

int main() {
    u2fh_rc ret;
    u2fh_devs *devs = NULL;
    unsigned num_devices;
    char *chal = NULL;

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

    chal = get_register_challenge(USERNAME, PASSWORD);
    printf("%s\n", chal);

done:
    free(chal);
    u2fh_devs_done(devs);
    u2fh_global_done();

    fprintf(stderr, "%s: %s\n", u2fh_strerror_name(ret), u2fh_strerror(ret));
    return ret;
}
