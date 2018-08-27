# Copyright (C) 2018 The u2fsperiments contributors

CFLAGS = -std=c11 -Wall -Wextra -ggdb -D_GNU_SOURCE -O0 -g
LDFLAGS =

fido2 = $(shell PKG_CONFIG_PATH=~/local/lib/pkgconfig pkg-config --cflags --libs libfido2)

all: client server

common.o: common.h common.c
	$(CC) -o common.o $(CFLAGS) -c common.c

base64.o: base64.h base64.c
	$(CC) -o base64.o $(CFLAGS) -c base64.c

client: client.c common.o base64.o
	$(CC) $(CFLAGS) $(LDFLAGS) $(fido2) -o client client.c common.o base64.o

server: server.c base64.o common.o
	$(CC) $(CFLAGS) $(LDFLAGS) $(fido2) -o server server.c base64.o common.o
