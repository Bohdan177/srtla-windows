CC = gcc
VERSION=$(shell git rev-parse --short HEAD)
CFLAGS=-g -O2 -Wall -DVERSION=\"$(VERSION)\"

ifeq ($(OS),Windows_NT)
    CFLAGS += -D_WIN32
    LDFLAGS += -lws2_32
endif

all: srtla_send srtla_rec

srtla_send: srtla_send.o common.o
	$(CC) srtla_send.o common.o -o srtla_send $(LDFLAGS)

# The receiver is compiled with its original main renamed so secure_main.c can
# consume --stream-id. The force-included hooks intercept only connect()/send()
# in srtla_rec.c; other translation units use the normal socket functions.
srtla_rec.o: srtla_rec.c streamid_auth.h streamid_auth_hooks.h
	$(CC) $(CFLAGS) -Dmain=srtla_original_main -include streamid_auth_hooks.h -c srtla_rec.c -o srtla_rec.o

srtla_rec: srtla_rec.o common.o streamid_auth.o secure_main.o
	$(CC) srtla_rec.o common.o streamid_auth.o secure_main.o -o srtla_rec $(LDFLAGS)

clean:
	rm -f *.o srtla_send srtla_rec
