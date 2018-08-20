/* Copyright (C) 2018 The u2fsperiments contributors */

#pragma once

#define ORIGIN "banana"

/* The library makes no guarantees about this, but this is what libu2f used
 * internally when I looked. */
#define MAX_REPLY_LEN 2048

int put(const char *v);

char *get();
