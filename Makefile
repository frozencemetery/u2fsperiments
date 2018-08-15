# Copyright (C) 2018 The u2fsperiments contributors

CFLAGS = -std=c11 -Wall -Wextra -ggdb
LDFLAGS =

u2fhost = $(shell pkg-config --cflags --libs u2f-host)

client: client.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(u2fhost) -o client client.c
