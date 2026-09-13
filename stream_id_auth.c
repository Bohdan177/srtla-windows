/*
 * Stream ID authentication shim for srtla_rec.
 *
 * The original receiver forwards raw SRT packets from SRTLA to the local
 * SRT listener. This shim interposes only the send() calls made by
 * srtla_rec and validates the SRT HSv5 Stream ID before the SRT conclusion
 * handshake is forwarded to the local listener.
 *
 * This keeps the original receiver logic intact and avoids adding libsrt
 * or any other runtime dependency.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#endif

#include "common.h"
#include "stream_id_auth.h"

#define MAX_STREAM_ID_LEN 512
#define SRT_CMD_SID 5
#define SRT_URQ_INDUCTION 1
#define SRT_URQ_CONCLUSION (-1)
#define AUTH_STATE_SLOTS 256

/*
 * Mirror the receiver's private connection/group structs so this translation
 * unit can identify which connection group owns a given local SRT socket.
 * Keep this in sync with srtla_rec.c if those structs change upstream.
 */
typedef struct srtla_conn {
  struct srtla_conn *next;
  struct sockaddr addr;
  time_t last_rcvd;
  int recv_idx;
  uint32_t recv_log[10];
  int reg_attempts;
  time_t next_reg_try_ms;
  int backoff_ms;
  int had_fatal_error;
} conn_t;

typedef struct srtla_conn_group {
  struct srtla_conn_group *next;
  conn_t *conns;
  time_t created_at;
  int srt_sock;
  struct sockaddr last_addr;
  char id[SRTLA_ID_LEN];
  uint64_t logical_group_id;
  group_state state;
  time_t next_srt_retry_ms;
  int srt_retry_attempts;
} conn_group_t;

extern conn_group_t *groups;

static char expected_stream_id[MAX_STREAM_ID_LEN + 1];
static size_t expected_stream_id_len = 0;
static int auth_enabled = 0;

typedef struct {
  uint64_t group_id;
  int used;
  int authenticated;
  int denied_logged;
} auth_state_t;

static auth_state_t auth_states[AUTH_STATE_SLOTS];

int srtla_rec_main(int argc, char **argv);

static uint16_t read_be16(const unsigned char *p) {
  uint16_t v;
  memcpy(&v, p, sizeof(v));
  return ntohs(v);
}

static uint32_t read_be32(const unsigned char *p) {
  uint32_t v;
  memcpy(&v, p, sizeof(v));
  return ntohl(v);
}

static int group_id_is_active(uint64_t group_id) {
  for (conn_group_t *g = groups; g != NULL; g = g->next) {
    if (g->logical_group_id == group_id) return 1;
  }
  return 0;
}

static conn_group_t *find_group_by_srt_socket(int sock) {
  for (conn_group_t *g = groups; g != NULL; g = g->next) {
    if (g->srt_sock == sock) return g;
  }
  return NULL;
}

static auth_state_t *get_auth_state(uint64_t group_id) {
  auth_state_t *free_slot = NULL;

  for (int i = 0; i < AUTH_STATE_SLOTS; i++) {
    if (auth_states[i].used && auth_states[i].group_id == group_id) {
      return &auth_states[i];
    }
    if (!auth_states[i].used && free_slot == NULL) {
      free_slot = &auth_states[i];
    }
  }

  /* Reclaim state belonging to groups that no longer exist. */
  if (free_slot == NULL) {
    for (int i = 0; i < AUTH_STATE_SLOTS; i++) {
      if (auth_states[i].used && !group_id_is_active(auth_states[i].group_id)) {
        memset(&auth_states[i], 0, sizeof(auth_states[i]));
        free_slot = &auth_states[i];
        break;
      }
    }
  }

  if (free_slot == NULL) return NULL;

  free_slot->used = 1;
  free_slot->group_id = group_id;
  free_slot->authenticated = 0;
  free_slot->denied_logged = 0;
  return free_slot;
}

static int constant_time_equal(const char *a, const char *b, size_t len) {
  unsigned char diff = 0;
  for (size_t i = 0; i < len; i++) {
    diff |= (unsigned char)a[i] ^ (unsigned char)b[i];
  }
  return diff == 0;
}

/*
 * Extract SRT_CMD_SID from a raw SRT HSv5 conclusion handshake.
 *
 * Return values:
 *   1  Stream ID found and copied to out
 *   0  no Stream ID extension present
 *  -1  malformed handshake/extension
 */
static int extract_stream_id(const unsigned char *pkt, size_t len,
                             char *out, size_t out_cap) {
  if (len < sizeof(srt_handshake_t)) return -1;
  if (read_be16(pkt) != SRT_TYPE_HANDSHAKE) return -1;

  size_t off = sizeof(srt_handshake_t);

  while (off + 4 <= len) {
    uint16_t cmd = read_be16(pkt + off);
    uint16_t words = read_be16(pkt + off + 2);
    size_t value_len = (size_t)words * 4;
    off += 4;

    if (value_len > len - off) return -1;

    if (cmd == SRT_CMD_SID) {
      if (value_len == 0 || value_len > MAX_STREAM_ID_LEN + 3) return -1;
      if (out_cap == 0) return -1;

      size_t written = 0;

      /*
       * SRT extension strings are carried as 32-bit words. The official
       * SRT implementation converts those words back to host order before
       * exposing the SID, so reproduce that conversion here.
       */
      for (size_t pos = 0; pos < value_len; pos += 4) {
        if (written + 4 >= out_cap) return -1;
        out[written++] = (char)pkt[off + pos + 3];
        out[written++] = (char)pkt[off + pos + 2];
        out[written++] = (char)pkt[off + pos + 1];
        out[written++] = (char)pkt[off + pos];
      }

      while (written > 0 && out[written - 1] == '\0') written--;
      if (written > MAX_STREAM_ID_LEN) return -1;
      out[written] = '\0';
      return 1;
    }

    off += value_len;
  }

  return 0;
}

/*
 * Return 1 when the packet may be forwarded to the local SRT listener.
 * Return 0 when it must be rejected.
 */
static int authorize_packet(conn_group_t *g, auth_state_t *state,
                            const unsigned char *pkt, size_t len) {
  if (!auth_enabled) return 1;
  if (state->authenticated) return 1;

  if (len < sizeof(srt_handshake_t) || read_be16(pkt) != SRT_TYPE_HANDSHAKE) {
    return 0;
  }

  /* handshake_type is at byte offset 36 in srt_handshake_t */
  int32_t handshake_type = (int32_t)read_be32(pkt + 36);

  /* Induction does not carry Stream ID. It must reach the local listener
     so that the normal SRT cookie exchange can proceed. */
  if (handshake_type == SRT_URQ_INDUCTION) return 1;

  if (handshake_type != SRT_URQ_CONCLUSION) return 0;

  char incoming[MAX_STREAM_ID_LEN + 1];
  int sid_result = extract_stream_id(pkt, len, incoming, sizeof(incoming));
  if (sid_result != 1) return 0;

  size_t incoming_len = strlen(incoming);
  if (incoming_len != expected_stream_id_len) return 0;
  if (!constant_time_equal(incoming, expected_stream_id, expected_stream_id_len)) return 0;

  state->authenticated = 1;
  state->denied_logged = 0;
  fprintf(stderr, "Group #%llu: Stream ID authentication accepted\n",
          (unsigned long long)g->logical_group_id);
  return 1;
}

static int reject_send(auth_state_t *state, uint64_t group_id) {
  if (!state->denied_logged) {
    fprintf(stderr,
            "Group #%llu: Stream ID authentication rejected; closing group\n",
            (unsigned long long)group_id);
    state->denied_logged = 1;
  }
#ifdef _WIN32
  WSASetLastError(WSAEACCES);
  return SOCKET_ERROR;
#else
  errno = EACCES;
  return -1;
#endif
}

#ifdef _WIN32
int WSAAPI srtla_auth_send(SOCKET sock, const char *buf, int len, int flags) {
  if (!auth_enabled) return send(sock, buf, len, flags);

  conn_group_t *g = find_group_by_srt_socket((int)sock);
  if (g == NULL) {
    /* Internal reachability/reconnect probes are not associated with a
       registered SRTLA group and should pass through untouched. */
    return send(sock, buf, len, flags);
  }

  auth_state_t *state = get_auth_state(g->logical_group_id);
  if (state == NULL) {
    fprintf(stderr, "Stream ID auth state table exhausted; rejecting packet\n");
    WSASetLastError(WSAENOBUFS);
    return SOCKET_ERROR;
  }

  if (!authorize_packet(g, state, (const unsigned char *)buf, (size_t)len)) {
    return reject_send(state, g->logical_group_id);
  }

  return send(sock, buf, len, flags);
}
#else
ssize_t srtla_auth_send(int sock, const void *buf, size_t len, int flags) {
  if (!auth_enabled) return send(sock, buf, len, flags);

  conn_group_t *g = find_group_by_srt_socket(sock);
  if (g == NULL) return send(sock, buf, len, flags);

  auth_state_t *state = get_auth_state(g->logical_group_id);
  if (state == NULL) {
    errno = ENOBUFS;
    return -1;
  }

  if (!authorize_packet(g, state, (const unsigned char *)buf, len)) {
    return reject_send(state, g->logical_group_id);
  }

  return send(sock, buf, len, flags);
}
#endif

static int configure_stream_id(const char *stream_id) {
  if (stream_id == NULL) return 0;

  size_t len = strlen(stream_id);
  if (len == 0 || len > MAX_STREAM_ID_LEN) {
    fprintf(stderr, "--stream-id must contain 1-%d UTF-8 bytes\n", MAX_STREAM_ID_LEN);
    return -1;
  }

  memcpy(expected_stream_id, stream_id, len + 1);
  expected_stream_id_len = len;
  auth_enabled = 1;
  return 0;
}

int main(int argc, char **argv) {
  const char *stream_id = NULL;
  char **forward_argv = calloc((size_t)argc + 1, sizeof(char *));
  if (forward_argv == NULL) {
    fprintf(stderr, "Failed to allocate argument list\n");
    return 1;
  }

  int forward_argc = 0;
  forward_argv[forward_argc++] = argv[0];

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--stream-id") == 0) {
      if (i + 1 >= argc) {
        fprintf(stderr, "--stream-id requires a value\n");
        free(forward_argv);
        return 1;
      }
      if (stream_id != NULL) {
        fprintf(stderr, "--stream-id may only be specified once\n");
        free(forward_argv);
        return 1;
      }
      stream_id = argv[++i];
      continue;
    }

    forward_argv[forward_argc++] = argv[i];
  }
  forward_argv[forward_argc] = NULL;

  if (stream_id == NULL) {
    stream_id = getenv("SRTLA_STREAM_ID");
  }

  if (stream_id != NULL) {
    if (configure_stream_id(stream_id) != 0) {
      free(forward_argv);
      return 1;
    }
    fprintf(stderr, "Stream ID authentication enabled\n");
  }

  int result = srtla_rec_main(forward_argc, forward_argv);
  free(forward_argv);
  return result;
}
