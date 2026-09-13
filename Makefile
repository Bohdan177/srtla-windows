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

srtla_rec: srtla_rec.o common.o stream_id_auth.o
	$(CC) srtla_rec.o common.o stream_id_auth.o -o srtla_rec $(LDFLAGS)

srtla_rec.o: srtla_rec.c stream_id_auth.h
	$(CC) $(CFLAGS) -Dmain=srtla_rec_main -Dsend=srtla_auth_send -include stream_id_auth.h -c srtla_rec.c -o srtla_rec.o

stream_id_auth.o: stream_id_auth.c stream_id_auth.h common.h
	$(CC) $(CFLAGS) -c stream_id_auth.c -o stream_id_auth.o

clean:
	rm -f *.o srtla_send srtla_rec
