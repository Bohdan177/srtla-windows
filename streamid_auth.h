#ifndef STREAMID_AUTH_H
#define STREAMID_AUTH_H

#include <stddef.h>

#ifdef _WIN32
#include <winsock2.h>
typedef SOCKET streamid_socket_t;
#else
#include <sys/types.h>
#include <sys/socket.h>
typedef int streamid_socket_t;
#endif

/*
 * Configure the exact SRT Stream ID that callers must present.
 * Returns 0 on success, -1 if the value is empty or too long.
 */
int streamid_auth_set_expected(const char *stream_id);

/* True when Stream ID authentication is enabled. */
int streamid_auth_enabled(void);

/* Socket wrappers used by srtla_rec.c via streamid_auth_hooks.h. */
#ifdef _WIN32
int streamid_auth_send(streamid_socket_t sock, const char *buf, int len, int flags);
int streamid_auth_connect(streamid_socket_t sock, const struct sockaddr *name, int namelen);
#else
ssize_t streamid_auth_send(streamid_socket_t sock, const void *buf, size_t len, int flags);
int streamid_auth_connect(streamid_socket_t sock, const struct sockaddr *name, socklen_t namelen);
#endif

#endif /* STREAMID_AUTH_H */
