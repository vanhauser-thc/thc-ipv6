#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include "thc-ipv6.h"

void noreply(int signo) {
  printf("Result: DNS server timeout\n");
  exit(1);
}

int main(int argc, char **argv) {
  char buf[1024], *dst, *host, *domain, *ptr, *ptr2;
  char b1[] = {0x28, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00};
  char b2[] = {0x00, 0x06, 0x00, 0x01};
  char b3[] = {0xc0, 0x0c, 0x00, 0x1c, 0x00, 0xff,
               0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  char b4[] = {0xc0, 0x00, 0x00, 0x1c, 0x00, 0x01,
               0x00, 0x01, 0x51, 0x80, 0x00, 0x10};
  struct addrinfo *ai;
  struct addrinfo  hints;
  int              sock, pid = getpid(), dlen = 0, i = 0, len;

  if (argc != 4) {
    printf("%s %s (c) 2020 by %s %s\n\n", argv[0], VERSION, AUTHOR, RESOURCE);
    printf("Syntax: %s dns-server full-qualified-host-dns-name ipv6address\n\n",
           argv[0]);
    printf("Example: %s dns.test.com myhost.sub.test.com ::1\n\n", argv[0]);
    exit(0);
  }

  if (getenv("THC_IPV6_PPPOE") != NULL || getenv("THC_IPV6_6IN4") != NULL)
    printf("WARNING: %s is not working with injection!\n", argv[0]);

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;
  if (getaddrinfo(argv[1], "53", &hints, &ai) != 0) {
    fprintf(stderr, "Error: unable to resolve dns server %s\n", argv[1]);
    exit(-1);
  }

  if ((sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) < 0) {
    fprintf(stderr, "Error: unable to resolve dns server %s\n", argv[1]);
    exit(-1);
  }

  if (connect(sock, ai->ai_addr, ai->ai_addrlen) < 0) {
    fprintf(stderr, "Error: unable to connect to dns server %s\n", argv[1]);
    exit(-1);
  }

  freeaddrinfo(ai);
  if ((dst = thc_resolve6(argv[3])) == NULL) {
    fprintf(stderr, "Error: not a valid IPv6 address: %s\n", argv[3]);
    exit(-1);
  }

  memcpy(buf, (char *)&pid + _TAKE2, 2);
  memcpy(buf + 2, b1, sizeof(b1));
  i = 2 + sizeof(b1);

  // domain-encoded-here foo.com == \x03foo\x03com\x00 == dlen
  host = argv[2];
  if ((domain = index(argv[2], '.')) == NULL) {
    fprintf(stderr, "Error: not a valid full-qualified-host-name: %s\n",
            argv[2]);
    exit(-1);
  }
  *domain = 0;
  ptr = domain;
  do {
    ptr++;
    if ((ptr2 = index(ptr, '.')) != NULL) *ptr2 = 0;
    len = strlen(ptr);
    buf[i++] = len;
    memcpy(buf + i, ptr, len);
    i += len;
    dlen += (len + 1);
    ptr = ptr2;
  } while (ptr != NULL);
  buf[i++] = 0;
  dlen++;

  memcpy(buf + i, b2, sizeof(b2));
  i += sizeof(b2);

  // host-encoded
  len = strlen(host);
  buf[i++] = len;
  memcpy(buf + i, host, len);
  i += len;
  memcpy(buf + i, b3, sizeof(b3));
  i += sizeof(b3);
  b4[1] = dlen + 16;
  memcpy(buf + i, b4, sizeof(b4));
  i += sizeof(b4);
  memcpy(buf + i, dst, 16);
  i += 16;

  send(sock, buf, i, 0);
  signal(SIGALRM, noreply);
  alarm(5);
  memset(buf, 0, sizeof(buf));
  recv(sock, buf, sizeof(buf), 0);
  alarm(0);

  if ((buf[3] & 9) == 9) {
    printf("Result: server not responsible for zone or update not supported\n");
    exit(1);
  } else if ((buf[3] & 15) == 1) {
    printf("Result: authentication required, update attempt failed\n");
    exit(1);
  } else if ((buf[3] & 1) == 1) {
    printf("Result: unknown error, update attempt failed\n");
    exit(1);
  } else
    printf("Result: update successful!\n");

  close(sock);
  return 0;
}
