# Copyright (C) 2018 The u2fsperiments contributors

CFLAGS = -std=c11 -Wall -Wextra -ggdb -D_GNU_SOURCE -O0 -g
LDFLAGS =

u2fhost = $(shell pkg-config --cflags --libs u2f-host)
u2fserver = $(shell pkg-config --cflags --libs u2f-server)

all: client server

common.o: common.h common.c
	$(CC) -o common.o $(CFLAGS) -c common.c

base64.o: base64.h base64.c
	$(CC) -o base64.o $(CFLAGS) -c base64.c

client: client.c common.o
	$(CC) $(CFLAGS) $(LDFLAGS) $(u2fhost) -o client client.c common.o

server: server.c base64.o common.o
	$(CC) $(CFLAGS) $(LDFLAGS) $(u2fserver) -o server server.c base64.o common.o
