/* Copyright (C) 2018 The u2fsperiments contributors */

#pragma once

#define ORIGIN "banana"

/* The library makes no guarantees about this, but this is what libu2f used
 * internally when I looked. */
#define MAX_REPLY_LEN 2048
#define CHALLENGE_LEN 32

/* libu2f incorrectly defines this as 43 and it makes their whole protocol
 * wonky - invalid base64 is passed around (missing trailing '='). */
#define B64U_LEN 44

int put(const char *v);

char *get();
