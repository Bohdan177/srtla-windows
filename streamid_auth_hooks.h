#ifndef STREAMID_AUTH_HOOKS_H
#define STREAMID_AUTH_HOOKS_H

/*
 * This file is force-included only when compiling srtla_rec.c.
 * It wraps connect()/send() so the receiver can validate the SRT Stream ID
 * without changing the upstream receiver source file.
 */
#include "streamid_auth.h"

#define connect streamid_auth_connect
#define send    streamid_auth_send

#endif /* STREAMID_AUTH_HOOKS_H */
