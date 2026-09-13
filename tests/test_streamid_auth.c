#ifndef _WIN32

#include "../streamid_auth.h"

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define HS_SIZE 64
#define SID_CMD 5

static size_t build_induction(unsigned char *pkt, size_t cap) {
  assert(cap >= HS_SIZE);
  memset(pkt, 0, HS_SIZE);
  pkt[0] = 0x80;
  pkt[1] = 0x00;
  pkt[39] = 0x01; /* handshake_type = 1, network byte order */
  return HS_SIZE;
}

static size_t build_conclusion(unsigned char *pkt, size_t cap, const char *sid, int include_sid) {
  memset(pkt, 0, cap);
  pkt[0] = 0x80;
  pkt[1] = 0x00;
  pkt[36] = 0xff;
  pkt[37] = 0xff;
  pkt[38] = 0xff;
  pkt[39] = 0xff;

  if (!include_sid) return HS_SIZE;

  size_t sid_len = strlen(sid);
  size_t words = (sid_len + 3u) / 4u;
  size_t value_len = words * 4u;
  assert(HS_SIZE + 4u + value_len <= cap);

  size_t off = HS_SIZE;
  pkt[off + 0] = 0x00;
  pkt[off + 1] = SID_CMD;
  pkt[off + 2] = (unsigned char)((words >> 8) & 0xff);
  pkt[off + 3] = (unsigned char)(words & 0xff);

  unsigned char padded[512] = {0};
  assert(value_len <= sizeof(padded));
  memcpy(padded, sid, sid_len);

  for (size_t pos = 0; pos < value_len; pos += 4) {
    pkt[off + 4 + pos + 0] = padded[pos + 3];
    pkt[off + 4 + pos + 1] = padded[pos + 2];
    pkt[off + 4 + pos + 2] = padded[pos + 1];
    pkt[off + 4 + pos + 3] = padded[pos + 0];
  }

  return HS_SIZE + 4u + value_len;
}

static void close_pair(int sv[2]) {
  close(sv[0]);
  close(sv[1]);
}

int main(void) {
  const char *secret = "vrfish-test-secret";
  unsigned char pkt[1024];
  unsigned char recvbuf[1024];
  int sv[2];

  assert(streamid_auth_set_expected(secret) == 0);
  assert(streamid_auth_enabled());

  /* Induction must pass so the listener can return its stateless cookie. */
  assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
  size_t n = build_induction(pkt, sizeof(pkt));
  assert(streamid_auth_send(sv[0], pkt, n, 0) == (ssize_t)n);
  assert(recv(sv[1], recvbuf, sizeof(recvbuf), 0) == (ssize_t)n);

  /* Matching Stream ID authenticates the socket and passes the conclusion. */
  n = build_conclusion(pkt, sizeof(pkt), secret, 1);
  assert(streamid_auth_send(sv[0], pkt, n, 0) == (ssize_t)n);
  assert(recv(sv[1], recvbuf, sizeof(recvbuf), 0) == (ssize_t)n);

  /* Once authenticated, ordinary traffic is allowed. */
  memset(pkt, 0x42, 32);
  assert(streamid_auth_send(sv[0], pkt, 32, 0) == 32);
  assert(recv(sv[1], recvbuf, sizeof(recvbuf), 0) == 32);
  close_pair(sv);

  /* Wrong Stream ID must fail closed. */
  assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
  n = build_conclusion(pkt, sizeof(pkt), "wrong-secret", 1);
  errno = 0;
  assert(streamid_auth_send(sv[0], pkt, n, 0) == -1);
  assert(errno == EACCES);
  close_pair(sv);

  /* Missing Stream ID in a conclusion must fail closed. */
  assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
  n = build_conclusion(pkt, sizeof(pkt), secret, 0);
  errno = 0;
  assert(streamid_auth_send(sv[0], pkt, n, 0) == -1);
  assert(errno == EACCES);
  close_pair(sv);

  /* Non-handshake traffic before authentication must fail closed. */
  assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
  memset(pkt, 0x11, 32);
  errno = 0;
  assert(streamid_auth_send(sv[0], pkt, 32, 0) == -1);
  assert(errno == EACCES);
  close_pair(sv);

  puts("streamid_auth tests passed");
  return 0;
}

#else
int main(void) { return 0; }
#endif
