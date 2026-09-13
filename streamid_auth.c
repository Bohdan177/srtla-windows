/*
 * Stream ID authentication for srtla_rec.
 *
 * The SRT caller sends SRTO_STREAMID in the HSv5 SRT_CMD_SID extension of
 * the conclusion handshake. We allow the initial induction handshake through
 * (so the local SRT listener can return its stateless cookie), but do not allow
 * the conclusion handshake or any media/control traffic through until the
 * configured Stream ID has been validated.
 */

#include "streamid_auth.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <errno.h>
#include <unistd.h>
#endif

#define SRT_TYPE_HANDSHAKE 0x8000
#define SRT_CMD_SID        5
#define SRT_FIXED_HS_SIZE  64
#define SRT_HS_TYPE_OFFSET 36
#define SRT_EXT_OFFSET     64
#define MAX_STREAM_ID_LEN  512

typedef enum {
  AUTH_PENDING = 0,
  AUTH_OK,
  AUTH_REJECTED
} auth_state_t;

typedef struct auth_socket_entry {
  streamid_socket_t sock;
  auth_state_t state;
  struct auth_socket_entry *next;
} auth_socket_entry_t;

static char expected_stream_id[MAX_STREAM_ID_LEN + 1];
static size_t expected_stream_id_len = 0;
static int auth_is_enabled = 0;
static auth_socket_entry_t *auth_sockets = NULL;

static unsigned long long socket_number(streamid_socket_t sock) {
  return (unsigned long long)(uintptr_t)sock;
}

static uint16_t read_be16(const unsigned char *p) {
  return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint32_t read_be32(const unsigned char *p) {
  return ((uint32_t)p[0] << 24) |
         ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) |
         (uint32_t)p[3];
}

static auth_socket_entry_t *find_socket(streamid_socket_t sock) {
  for (auth_socket_entry_t *entry = auth_sockets; entry != NULL; entry = entry->next) {
    if (entry->sock == sock) return entry;
  }
  return NULL;
}

static auth_socket_entry_t *get_or_create_socket(streamid_socket_t sock) {
  auth_socket_entry_t *entry = find_socket(sock);
  if (entry != NULL) return entry;

  entry = (auth_socket_entry_t *)calloc(1, sizeof(*entry));
  if (entry == NULL) return NULL;

  entry->sock = sock;
  entry->state = AUTH_PENDING;
  entry->next = auth_sockets;
  auth_sockets = entry;
  return entry;
}

static void forget_socket(streamid_socket_t sock) {
  auth_socket_entry_t **link = &auth_sockets;
  while (*link != NULL) {
    if ((*link)->sock == sock) {
      auth_socket_entry_t *dead = *link;
      *link = dead->next;
      free(dead);
      return;
    }
    link = &((*link)->next);
  }
}

static int secure_equal(const unsigned char *actual, size_t actual_len) {
  size_t max_len = actual_len > expected_stream_id_len ? actual_len : expected_stream_id_len;
  unsigned int diff = (unsigned int)(actual_len ^ expected_stream_id_len);

  for (size_t i = 0; i < max_len; ++i) {
    unsigned char a = i < actual_len ? actual[i] : 0;
    unsigned char b = i < expected_stream_id_len ? (unsigned char)expected_stream_id[i] : 0;
    diff |= (unsigned int)(a ^ b);
  }

  return diff == 0;
}

/*
 * Decode the SRT Stream ID extension from a conclusion handshake.
 *
 * Return values:
 *   1  = matching Stream ID
 *   0  = not a conclusion handshake (authentication not decidable yet)
 *  -1  = conclusion handshake with missing/mismatched Stream ID
 *  -2  = malformed conclusion handshake
 */
static int validate_conclusion_stream_id(const void *buffer, size_t len) {
  const unsigned char *pkt = (const unsigned char *)buffer;

  if (len < SRT_FIXED_HS_SIZE) return 0;
  if (read_be16(pkt) != SRT_TYPE_HANDSHAKE) return 0;

  /* Caller-listener HSv5 conclusion uses request type -1 (0xffffffff). */
  if ((int32_t)read_be32(pkt + SRT_HS_TYPE_OFFSET) != -1) return 0;

  size_t offset = SRT_EXT_OFFSET;
  while (offset + 4 <= len) {
    uint16_t command = read_be16(pkt + offset);
    uint16_t word_count = read_be16(pkt + offset + 2);
    size_t value_len = (size_t)word_count * 4u;

    if (value_len > len - offset - 4) return -2;

    if (command == SRT_CMD_SID) {
      if (value_len == 0 || value_len > MAX_STREAM_ID_LEN) return -2;

      unsigned char decoded[MAX_STREAM_ID_LEN];
      size_t decoded_len = 0;
      const unsigned char *value = pkt + offset + 4;

      /*
       * SRT string extensions are stored as 32-bit words. On the wire each
       * word is byte-swapped, so restore the original byte order per word.
       */
      for (size_t pos = 0; pos < value_len; pos += 4) {
        decoded[decoded_len++] = value[pos + 3];
        decoded[decoded_len++] = value[pos + 2];
        decoded[decoded_len++] = value[pos + 1];
        decoded[decoded_len++] = value[pos + 0];
      }

      while (decoded_len > 0 && decoded[decoded_len - 1] == 0) {
        decoded_len--;
      }

      return secure_equal(decoded, decoded_len) ? 1 : -1;
    }

    offset += 4 + value_len;
  }

  /* A conclusion handshake without SRT_CMD_SID fails closed. */
  return -1;
}

static int reject_send(streamid_socket_t sock, const char *reason) {
  fprintf(stderr,
          "Stream ID authentication: rejected socket %llu (%s)\n",
          socket_number(sock), reason);
#ifdef _WIN32
  WSASetLastError(WSAEACCES);
  return SOCKET_ERROR;
#else
  errno = EACCES;
  return -1;
#endif
}

int streamid_auth_set_expected(const char *stream_id) {
  if (stream_id == NULL) return -1;

  size_t len = strlen(stream_id);
  if (len == 0 || len > MAX_STREAM_ID_LEN) return -1;

  memcpy(expected_stream_id, stream_id, len + 1);
  expected_stream_id_len = len;
  auth_is_enabled = 1;

  fprintf(stderr,
          "Stream ID authentication enabled (%zu-byte secret; value hidden)\n",
          expected_stream_id_len);
  return 0;
}

int streamid_auth_enabled(void) {
  return auth_is_enabled;
}

#ifdef _WIN32
int streamid_auth_connect(streamid_socket_t sock, const struct sockaddr *name, int namelen) {
#else
int streamid_auth_connect(streamid_socket_t sock, const struct sockaddr *name, socklen_t namelen) {
#endif
  /* Socket descriptors/handles can be reused. Never inherit old auth state. */
  forget_socket(sock);
  return connect(sock, name, namelen);
}

#ifdef _WIN32
int streamid_auth_send(streamid_socket_t sock, const char *buf, int len, int flags) {
  if (!auth_is_enabled) return send(sock, buf, len, flags);
  if (len <= 0) return send(sock, buf, len, flags);
#else
ssize_t streamid_auth_send(streamid_socket_t sock, const void *buf, size_t len, int flags) {
  if (!auth_is_enabled) return send(sock, buf, len, flags);
  if (len == 0) return send(sock, buf, len, flags);
#endif

  auth_socket_entry_t *entry = get_or_create_socket(sock);
  if (entry == NULL) {
    return reject_send(sock, "unable to allocate authentication state");
  }

  if (entry->state == AUTH_REJECTED) {
    return reject_send(sock, "connection already rejected");
  }

  if (entry->state == AUTH_OK) {
    return send(sock, buf, len, flags);
  }

  int validation = validate_conclusion_stream_id(buf, (size_t)len);
  if (validation == 1) {
    entry->state = AUTH_OK;
    fprintf(stderr,
            "Stream ID authentication: accepted socket %llu\n",
            socket_number(sock));
    return send(sock, buf, len, flags);
  }

  if (validation < 0) {
    entry->state = AUTH_REJECTED;
    return reject_send(sock,
                       validation == -2 ? "malformed Stream ID handshake" :
                                          "missing or incorrect Stream ID");
  }

  /*
   * Only the induction handshake is allowed before authentication. Any other
   * SRT packet before a valid conclusion is rejected fail-closed.
   */
  const unsigned char *pkt = (const unsigned char *)buf;
  if ((size_t)len >= SRT_FIXED_HS_SIZE && read_be16(pkt) == SRT_TYPE_HANDSHAKE &&
      (int32_t)read_be32(pkt + SRT_HS_TYPE_OFFSET) == 1) {
    return send(sock, buf, len, flags);
  }

  entry->state = AUTH_REJECTED;
  return reject_send(sock, "traffic arrived before Stream ID authentication");
}
