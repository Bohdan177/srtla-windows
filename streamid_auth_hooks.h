#ifndef STREAMID_AUTH_HOOKS_H
#define STREAMID_AUTH_HOOKS_H

/*
 * This file is force-included only when compiling srtla_rec.c.
 * It wraps connect()/send()/close() so the receiver can validate the SRT
 * Stream ID and never reuse authentication state with a recycled socket.
 */
#include "streamid_auth.h"

#define connect streamid_auth_connect
#define send    streamid_auth_send
#define close   streamid_auth_close

#endif /* STREAMID_AUTH_HOOKS_H */
