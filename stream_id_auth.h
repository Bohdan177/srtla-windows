#ifndef SRTLA_STREAM_ID_AUTH_H
#define SRTLA_STREAM_ID_AUTH_H

#ifdef _WIN32
#include <winsock2.h>
int WSAAPI srtla_auth_send(SOCKET sock, const char *buf, int len, int flags);
#else
#include <sys/types.h>
#include <sys/socket.h>
ssize_t srtla_auth_send(int sock, const void *buf, size_t len, int flags);
#endif

#endif
