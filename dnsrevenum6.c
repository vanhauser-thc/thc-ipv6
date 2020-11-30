/*
 * Simple and fast Reverse DNS Enumerator for IPv6
 *   - detects wildcard DNS servers
 *   - adapts to lossy/slow DNS server
 *   - fast but non-flooding
 *   - specify the reverse domain as 2001:db8::/56
 *                                or 0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa
 *
 * (c) 2020 by Marc "van Hauser" Heuse <vh(at)thc.org> or <mh(at)mh-sec.de>
 * The AGPL v3 license applies to this code.
 *
 * Compile: gcc -O2 -o dnsrevenum6 dnsrevenum6.c thc-ipv6-lib.o -lcrypto -lssl
 * -lpcap
 *
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <ctype.h>
#include <string.h>
#include <time.h>
#include "thc-ipv6.h"

// do not set below 2
#define WAITTIME_START 2

int sock, len, buf_len, waittime = WAITTIME_START, wait, found = 0, tcp = 0,
                        tcp_offset = 0;
unsigned char range[33], buf_start[12], buf_end[14], buf[512], buf2[1024],
    name[512], dst6[16], *prg, *dst, cnt = 0;

int dnssocket(char *server) {
  struct addrinfo *ai;
  struct addrinfo  hints;
  int              s;
  struct timeval   tv;

  tv.tv_sec = 1;   /* 1 sec Timeout */
  tv.tv_usec = 0;  // Not init'ing this can cause strange errors
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  if (tcp) {
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
  } else {
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
  }
  if (getaddrinfo(server, "53", &hints, &ai) != 0) {
    fprintf(stderr, "Error: unable to resolve dns server %s!\n", server);
    exit(-1);
  }
  if ((s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) < 0) {
    fprintf(stderr, "Error: unable to resolve dns server %s!\n", server);
    exit(-1);
  }

  setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval));

  if (connect(s, ai->ai_addr, ai->ai_addrlen) < 0) {
    fprintf(stderr, "Error: unable to connect to dns server %s!\n", server);
    exit(-1);
  }
  freeaddrinfo(ai);

  return s;
}

unsigned char tohex(unsigned char c) {
  if (c < 10)
    return (c + '0');
  else
    return (c + 'a' - 10);
}

unsigned char tochar(unsigned char c) {
  if (c >= '0' && c <= '9')
    return (c - '0');
  else
    return (tolower(c) - 'a' + 10);
}

void ignore(int signal) {
  wait = 0;
  if (debug) printf("interrupted!\n");
  return;
}

int send_range() {
  int i, recv_len = sizeof(buf2);

  for (i = 0; i < 32; i++) {
    buf[tcp_offset + sizeof(buf_start) + i * 2] = 1;
    buf[tcp_offset + sizeof(buf_start) + i * 2 + 1] = range[31 - i];
  }
  memcpy(buf + tcp_offset + sizeof(buf_start) + 64, buf_end, sizeof(buf_end));
  buf_len = sizeof(buf_start) + 64 + sizeof(buf_end);
  buf[tcp_offset + 0] = 254;
  buf[tcp_offset + 1] = cnt++;
  if (tcp) {
    buf[0] = buf_len / 256;
    buf[1] = buf_len % 256;
    buf_len += 2;
  }

  if (send(sock, buf, buf_len, 0) < 0) {
    fprintf(stderr, "Error: Can not send to network!\n");
    exit(-1);
  } else
    usleep(5);

  if (tcp) {
    alarm(waittime + 1);
    len = recv(sock, buf2, 2, 0);
    alarm(0);
    if (len != 2) return -1;
    recv_len = (buf2[0] << 8) + buf2[1];
    if (recv_len > sizeof(buf2)) return -1;
  }

  alarm(waittime + 1);
  if ((len = recv(sock, buf2, recv_len, 0)) > 20) {
    alarm(0);
    if ((buf2[3] & 3) == 0 && buf2[7] == 1)
      return 0;
    else
      return 1;
  }
  alarm(0);

  return -1;
}

int deeper(int depth) {
  unsigned char r[16], *ptr2, *foo;
  int           i, j, ok = 0, rs = 0, len, clen, nlen, recv_len = sizeof(buf2);

  if (depth > 31) return -1;
  memset(r, 0, sizeof(r));

  // generate base packet
  cnt++;
  buf[tcp_offset + 1] = cnt;
  for (i = 0; i < depth; i++) {
    buf[tcp_offset + sizeof(buf_start) + 2 + i * 2] = 1;
    buf[tcp_offset + sizeof(buf_start) + 2 + i * 2 + 1] = range[depth - i - 1];
  }
  memcpy(buf + tcp_offset + sizeof(buf_start) + 2 + depth * 2, buf_end,
         sizeof(buf_end));
  buf_len = sizeof(buf_start) + 2 + depth * 2 + sizeof(buf_end);

  // loop to finish generation and send
redo:
  for (i = 0; i < 16; i++) {
    if (r[i] == 0) {
      buf[tcp_offset + 0] = i;
      buf[tcp_offset + 13] = tohex(i);

      if (tcp) {
        buf[0] = buf_len / 256;
        buf[1] = buf_len % 256;
        buf_len += 2;
      }

      if (send(sock, buf, buf_len, 0) < 0) {
        fprintf(stderr, "Error: can not send to network!\n");
        exit(-1);
      } else
        usleep(5);
    }
  }

  // recveive and process replies
  wait = 1;
  alarm(waittime);
  while (ok == 0 && wait == 1) {
    if (tcp) {
      recv(sock, buf2, 2, 0);
      recv_len = (buf2[0] << 8) + buf2[1];
      if (recv_len > sizeof(buf2)) {
        close(sock);
        sock = dnssocket(dst);
        goto redo;
      }
    }
    if ((len = recv(sock, buf2, recv_len, 0)) > 70 && buf2[1] == cnt) {
      i = (buf2[0] & 15);
      if ((buf2[3] & 3) == 0) {
        if (depth == 31) {
          r[i] = 3;
          if (buf2[7] == 1) {
            found++;
            strcpy(name, "Found: ");
            ptr2 = buf2 + 12;
            i = 0;
            while (i < 32 && *ptr2 == 1) {
              if (i % 2 == 0)
                j = tochar(ptr2[1]);
              else
                dst6[15 - i / 2] = (tochar(ptr2[1]) * 16) + j;
              ptr2 += 2;
              i++;
            }
            foo = thc_ipv62notation(dst6);
            strcat(name, foo);
            free(foo);
            strcat(name, " is ");
            ptr2 = buf2 + 102;
            while (*ptr2 != 0 && ptr2 + *ptr2 + 1 <= buf2 + len) {
              clen = *ptr2;
              nlen = *(ptr2 + clen + 1);
              *(ptr2 + clen + 1) = 0;
              strncat(name, ptr2 + 1, sizeof(name) - strlen(name) - 4);
              strcat(name, ".");
              *(ptr2 + *ptr2 + 1) = nlen;
              ptr2 += clen + 1;
            }
            if (debug) {
              strcat(name, " is ");
              ptr2 = buf2 + 12;
              while (*ptr2 != 0 && ptr2 + *ptr2 + 1 <= buf2 + len) {
                clen = *ptr2;
                nlen = *(ptr2 + clen + 1);
                *(ptr2 + clen + 1) = 0;
                strncat(name, ptr2 + 1, sizeof(name) - strlen(name) - 4);
                strcat(name, ".");
                *(ptr2 + *ptr2 + 1) = nlen;
                ptr2 += clen + 1;
              }
            }
            printf("%s\n", name);
          }
        } else
          r[i] = 2;
      } else
        r[i] = 1;
      rs++;
    }

    if (rs == 16) ok = 1;
  }
  alarm(0);

  if (ok == 1 || rs == 16) {  // all packets received
    for (i = 0; i < 16; i++)
      if (r[i] == 2) {
        range[depth] = tohex(i);
        deeper(depth + 1);
      }
  } else {  // packet loss / timeout
    if (rs < 16) waittime++;
    if (rs < 11) waittime++;
    if (rs < 6) waittime++;
    if (rs < 2) waittime++;
    if ((rs == 0 && (waittime >= WAITTIME_START + 6)) || waittime > 15) {
      fprintf(stderr,
              "Error: DNS Server %s is not answering or not reliable enough "
              "anymore!\n",
              dst);
      exit(-1);
    }
    fprintf(stderr,
            "Warning: packet loss, increasing response timeout to %d seconds\n",
            waittime);
    close(sock);
    sock = dnssocket(dst);
    goto redo;
  }

  return rs;
}

int main(int argc, char *argv[]) {
  unsigned char *ptr, *ptr2, *dest, range_start = 0;
  ;
  int i, j, k, ok;

  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  prg = argv[0];

  if (argc > 1 && strncmp(argv[1], "-t", 2) == 0) {
    tcp = 1;
    tcp_offset = 2;
    argv++;
    argc--;
  }

  if (argc < 3) {
    printf("%s %s (c) 2020 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
    printf("Syntax: %s [-t] dns-server ipv6address\n\n", argv[0]);
    printf(
        "Performs a fast reverse DNS enumeration and is able to cope with slow "
        "servers.\n");
    printf(
        "Option -t enables TCP instead of UDP (use this if you get many "
        "timeouts)\n");
    printf("Examples:\n");
    printf("  %s dns.test.com 2001:db8:42a8::/48\n", argv[0]);
    printf("  %s -t dns.test.com 8.a.2.4.8.b.d.0.1.0.0.2.ip6.arpa\n", argv[0]);
    exit(0);
  }

  if (getenv("THC_IPV6_PPPOE") != NULL || getenv("THC_IPV6_6IN4") != NULL)
    printf("WARNING: %s is not working with injection!\n", argv[0]);

  if (strcmp(argv[1], "-d") == 0) {
    debug = 1;
    argv++;
    argc--;
  }

  dst = argv[1];
  ptr = argv[2];

  srand(time(NULL) + getpid());
  memset(range, 0, sizeof(range));
  memset(buf, 0, sizeof(buf));
  memset(buf_start, 0, sizeof(buf_start));
  memset(buf_end, 0, sizeof(buf_end));

  ok = 1;
  if ((*ptr != '.') && (index((char *)(uintptr_t)ptr, '.') != NULL) &&
      ((ptr2 = (unsigned char *)(uintptr_t)strcasestr((char *)(uintptr_t)ptr,
                                                      ".ip6.arpa")) != NULL)) {
    *ptr2 = 0;
    for (i = strlen(ptr) - 1; i >= 0 && ok == 1; i--) {
      if ((ptr[i] >= 'A' && ptr[i] <= 'F') ||
          (ptr[i] >= 'a' && ptr[i] <= 'f') ||
          (ptr[i] >= '0' && ptr[i] <= '9')) {
        range[range_start++] = (char)tolower(ptr[i]);
        if (i >= 2) {
          if (ptr[i - 1] != '.')
            ok = 0;
          else
            i--;
        }
      } else
        ok = 0;
    }

  } else if (index(ptr, ':') != NULL && (ptr2 = index(ptr, '/')) != NULL) {
    *ptr2++ = 0;
    len = atoi(ptr2);
    if (len % 4 > 0 || len < 4 || len > 124) {
      fprintf(stderr,
              "Error: invalid prefix length, must be a multiple of 4!\n");
      exit(-1);
    }
    if (len < 48)
      fprintf(stderr,
              "Warning: prefix length is smaller than 48, usually this does "
              "not work.\n");
    if (len % 8 > 0)
      j = (len / 8) + 1;
    else
      j = len / 8;
    if ((dest = thc_resolve6(ptr)) == NULL) {
      fprintf(stderr, "Error: %s gives not a valid IPv6 address\n", ptr);
      exit(-1);
    }
    for (i = 0; i < j; i++) {
      range[i * 2] = tohex(dest[i] / 16);
      range[i * 2 + 1] = tohex(dest[i] % 16);
    }
    range_start = len / 4;
  } else
    ok = 0;

  if (ok == 0) {
    fprintf(stderr, "Error: invalid IPv6 address specified: %s\n", argv[2]);
    exit(-1);
  }

  memset(buf_start, 0, sizeof(buf_start));
  memset(buf_end, 0, sizeof(buf_end));
  buf_start[2] = 1;
  buf_start[5] = 1;
  memcpy(buf + tcp_offset, buf_start, sizeof(buf_start));
  buf[tcp_offset + 12] = 1;
  buf_end[0] = 3;
  strcpy(buf_end + 1, "ip6");
  buf_end[4] = 4;
  strcpy(buf_end + 5, "arpa");
  buf_end[11] = 0x0c;
  buf_end[13] = 1;
  signal(SIGALRM, ignore);

  printf("Starting DNS reverse enumeration of %s on server %s\n", ptr, dst);

  // first: wildcard check
  ok = 0;
  k = 0;
  sock = dnssocket(dst);

  for (j = 0; j < 5; j++) {
    for (i = range_start; i < 32; i++)
      range[i] = tohex(rand() % 16);
    switch (send_range()) {
      case 0:
        ok++;
        break;
      case -1:
        k++;
        close(sock);
        sock = dnssocket(dst);
        break;
      default:
        i = 0;  // ignored
    }
  }

  if (ok > 2) {
    fprintf(stderr,
            "Error: Wildcard configured in DNS server, not possible to "
            "enumerate!\n");
    return -1;
  }
  if (k == 5) {
    fprintf(stderr, "Error: DNS server %s sent no replies!\n", dst);
    return -1;
  } else if (k > 0)
    waittime += 2;

  // starting the search
  i = deeper(range_start);

  printf("Found %d entr%s.\n", found, found == 1 ? "y" : "ies");
  if (found == 0)
    return 1;
  else
    return 0;
}
