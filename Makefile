# Copyright (C) 2018 The u2fsperiments contributors

CFLAGS = -std=c11 -Wall -Wextra -ggdb -D_GNU_SOURCE
LDFLAGS =

u2fhost = $(shell pkg-config --cflags --libs u2f-host)
curl = $(shell pkg-config --cflags --libs libcurl)

client: client.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(u2fhost) $(curl) -o client client.c
