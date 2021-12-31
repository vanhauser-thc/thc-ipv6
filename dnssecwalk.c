/*
 * Simple DNSSEC walker requiring no special libraries.
 *
 * (c) 2022 by Marc "van Hauser" Heuse <vh(at)thc.org> or <mh(at)mh-sec.de>
 * The AGPL v3 license applies to this code.
 *
 * Works against DNSSEC servers which have NSEC enabled (default)
 * instead of NSEC3 :-)
 *
 * Compile simply as gcc -O2 -o dnssecwalk dnssecwalk.c
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <ctype.h>
#include "thc-ipv6.h"

#define RETRY 5
// int debug = 0;
int   errcnt = 0, sock, ensure = 0, dores = -1, tcp = 0, tcp_offset = 0;
char *dst, first[256], beforesub[256], firstsub[256];

int dnssocket(char *server) {
  struct addrinfo *ai;
  struct addrinfo  hints;
  int              s;

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
    fprintf(stderr, "Error: unable to resolve dns server %s\n", dst);
    exit(-1);
  }
  if ((s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) < 0) {
    fprintf(stderr, "Error: unable to get a socket %s\n", dst);
    exit(-1);
  }
  if (connect(s, ai->ai_addr, ai->ai_addrlen) < 0) {
    fprintf(stderr, "Error: unable to connect to dns server %s\n", dst);
    exit(-1);
  }
  freeaddrinfo(ai);

  return s;
}

void noreply(int signo) {
  ++errcnt;
  if (errcnt < RETRY) {
    fprintf(stderr, "Warning: DNS server timeout (%d of %d retries)\n", errcnt,
            RETRY);
    close(sock);
    sock = -1;
    return;
  } else {
    fprintf(stderr, "Error: Giving up on DNS server, too many timeouts\n");
    exit(1);
  }
}

int main(int argc, char **argv) {
  unsigned char buf[1024], buf2[1024];
  char *        ptr, *ptr2, nexthost[256], domain[256];
  char b1[] = {0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  char b2[] = {0x00, 0x2f, 0x00, 0x01};
  int  pid = getpid(), dlen = 0, i = 0, fixi, len, ok = 1, cnt = 0, errcntbak,
      sub = 0, recv_len;
  struct addrinfo      hints, *res, *p;
  struct sockaddr_in6 *ipv6, *q;
  struct sockaddr_in * ipv4, *q4;
  char                 ipv4str[16], ipv6str[64];
  void *               addr, *addr4;

  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  if (argc < 3) {
    printf(
        "%s %s (c) 2022 by Marc Heuse <mh@mh-sec.de> http://www.mh-sec.de\n\n",
        argv[0], VERSION);
    printf("Syntax: %s [-e46t] dns-server domain\n\n", argv[0]);
    printf(
        "Options:\n -e  ensure that the domain is present in found addresses, "
        "quit otherwise\n -4  resolve found entries to IPv4 addresses\n -6  "
        "resolve found entries to IPv6 addresses\n -t  use TCP instead of "
        "UDP\n\n");
    printf(
        "Perform DNSSEC NSEC walking.\n\nExample: %s dns.test.com test.com\n",
        argv[0]);
    exit(0);
  }

  while ((i = getopt(argc, argv, "e46t")) >= 0) {
    switch (i) {
      case 'e':
        ensure = 1;
        break;
      case 't':
        tcp = 1;
        tcp_offset = 2;
        break;
      case '4':
        if (dores == -1)
          dores = AF_INET;
        else
          dores = 0;
        break;
      case '6':
        if (dores == -1)
          dores = AF_INET6;
        else
          dores = 0;
        break;
      default:
        fprintf(stderr, "Error: unknown option -%c\n", i);
        exit(-1);
    }
  }

  if (optind + 2 > argc) {
    fprintf(stderr,
            "Error: you must specify the DNS server to query and the domain\n");
    exit(-1);
  }

  dst = argv[optind];
  sock = dnssocket(dst);

  for (i = 0; i < strlen(argv[optind]); i++)
    argv[optind][i] = (char)tolower((int)argv[optind][i]);
  for (i = 0; i < strlen(argv[optind + 1]); i++)
    argv[optind + 1][i] = (char)tolower((int)argv[optind + 1][i]);

  if (index(argv[optind + 1], '.') == NULL) {
    fprintf(stderr, "Error: not a valid domain (must be at least \".\"): %s\n",
            argv[optind + 1]);
    exit(-1);
  }
  strncpy(domain, argv[optind + 1], sizeof(nexthost) - 2);
  domain[sizeof(domain) - 2] = 0;
  if (domain[strlen(domain) - 1] != '.') strcat(domain, ".");
  strncpy(nexthost, argv[optind + 1], sizeof(nexthost) - 1);
  nexthost[sizeof(nexthost) - 1] = 0;

  memcpy(buf + tcp_offset, (char *)&pid + _TAKE2, 2);
  memcpy(buf + tcp_offset + 2, b1, sizeof(b1));
  i = 2 + sizeof(b1) + tcp_offset;
  fixi = i;

  if (dores >= 0) {
    memset((char *)&hints, 0, sizeof(hints));
    hints.ai_family = dores;
  }

  printf("Starting DNSSEC walking on server %s about %s (%s)\n", dst, domain,
         tcp == 0 ? "UDP" : "TCP");
  while (ok == 1) {
    ptr = nexthost;
    i = fixi;

    // domain-encoded-here foo.com == \x03foo\x03com\x00 == dlen
    if (strcmp(ptr, ".") != 0) do {
        if ((ptr2 = index(ptr, '.')) != NULL) *ptr2 = 0;
        len = strlen(ptr);
        buf[i++] = len;
        memcpy(buf + i, ptr, len);
        i += len;
        dlen += (len + 1);
        ptr = ptr2;
        if (ptr != NULL) ptr++;
      } while (ptr != NULL && *ptr != 0);
    buf[i++] = 0;

    memcpy(buf + i, b2, sizeof(b2));
    i += sizeof(b2);
    dlen = i;

    if (tcp) {
      int data_len = dlen - 2;
      buf[0] = data_len / 256;
      buf[1] = data_len % 256;
    }

  resend:
    if (send(sock, buf, dlen, 0) < 0) {
      fprintf(stderr, "Error: can not send to network\n");
      exit(-1);
    }

    /*
        if (debug) {
          len = i;
          for (i = 0; i < len; i++) {
            if (i % 16 == 0)
              printf(" ");
            if (i % 8 == 0)
              printf(" ");
            printf("%02x ", buf[i]);
            if (i % 16 == 15)
              printf("\n");
          }
          printf("\n\n");
        }
    */

    errcntbak = errcnt;
    signal(SIGALRM, noreply);
    memset(buf2, 0, sizeof(buf2));
    if (tcp) {
      alarm(5);
      len = recv(sock, buf2, 2, 0);
      alarm(0);
      if (len != 2) {
        close(sock);
        sock = dnssocket(dst);
        recv_len = 0;
        if (errcntbak == errcnt) errcnt++;
        if ((errcntbak != errcnt) && errcnt > 0 && errcnt <= RETRY) goto resend;
        if (RETRY < errcnt || len < 10) noreply(0);
      } else
        recv_len =
            (unsigned int)((unsigned int)buf2[0] << 8) + (unsigned int)buf2[1];
      if (sock == -1) sock = dnssocket(dst);
    } else
      recv_len = sizeof(buf2);
    alarm(5);
    len = recv(sock, buf2, recv_len, 0);
    alarm(0);
    if (sock == -1) sock = dnssocket(dst);
    if (len <= 0 && errcntbak == errcnt) errcnt++;
    if ((errcntbak != errcnt) && errcnt > 0 && errcnt <= RETRY) goto resend;
    if (RETRY < errcnt || len < 10) noreply(0);

    if ((buf2[3] & 9) == 9 || (buf2[3] & 15) == 2) {
      printf("Result: server not responsible for domain %s\n", nexthost);
      exit(1);
    } else if (buf2[3] == 5) {
      printf(
          "Result: server does not support NSEC, dnssec walking not "
          "possible\n");
      exit(1);
    } else if ((buf2[3] & 15) > 0) {
      printf("Result: unknown error (%d)\n", (buf2[3] & 15));
      exit(1);
    } else if (buf2[7] != 1) {
      printf(
          "Result: server does not support NSEC, dnssec walking not "
          "possible\n");
      exit(1);
    }

    ptr = (char *)(buf2 + i);
    while (ptr < (char *)(buf2 + len) && *ptr != 0x2f)
      ptr++;
    ptr += 9;
    ptr2 = ptr + 1;
    i = *ptr;
    if (*ptr == 0) {
      ptr++;
    } else {
      while (i != 0) {
        ptr += i + 1;
        i = *ptr;
        *ptr = '.';
      }
    }
    *ptr++ = '.';
    *ptr = 0;
    if (*ptr2 != 0) {
      for (i = 0; i < strlen(ptr2); i++)
        ptr2[i] = (char)tolower((int)ptr2[i]);
      if (strcasecmp(ptr2, domain) == 0)
        ok = 2;
      else {
        if (sub == 1) {
          if (strcmp(firstsub, ptr2) == 0 || strcmp(beforesub, ptr2) == 0) {
            fprintf(stderr, "Error: loop detected (sub), aborting\n");
            exit(-1);
          }
        }
        if (cnt != 0) {
          if ((ptr2[2 + strlen(ptr2)] & 2) == 2) {
            fprintf(stderr,
                    "Warning: start of a sub domain: %s - following items can "
                    "not be enumerated automatically (don't blame the tool, "
                    "NSEC is broken. Brute force the next valid hostname and "
                    "rerun the tool with hostname++.domain.)\n",
                    nexthost);
            sub = 1;
            strcpy(beforesub, nexthost);
            strncpy(firstsub, ptr2, sizeof(firstsub) - 1);
            firstsub[sizeof(firstsub) - 1] = 0;
          }
          if (strcmp(ptr2, first) == 0 || strcmp(ptr2, nexthost) == 0) {
            fprintf(stderr, "Error: loop detected, aborting\n");
            exit(-1);
          }
          strncpy(nexthost, ptr2, sizeof(nexthost) - 1);
          nexthost[sizeof(nexthost) - 1] = 0;
        } else {
          strncpy(nexthost, ptr2, sizeof(nexthost) - 1);
          nexthost[sizeof(nexthost) - 1] = 0;
          strcpy(first, nexthost);
        }
        if (ensure && strstr(nexthost, domain) == NULL) {
          fprintf(stderr, "Error: domain %s not found in result %s, exiting\n",
                  domain, nexthost);
          exit(-1);
        }
        if (dores != -1) {
          if (getaddrinfo(nexthost, NULL, &hints, &res) == 0) {
            printf("Found: %s", nexthost);
            q = NULL;
            q4 = NULL;
            for (p = res; p != NULL; p = p->ai_next) {
              if (p->ai_family == AF_INET6) {  // IPv6
                ipv6 = (struct sockaddr_in6 *)p->ai_addr;
                addr = &(ipv6->sin6_addr);
                // convert the IP to a string and print it:
                if (q == NULL ||
                    memcmp(&ipv6->sin6_addr, &q->sin6_addr, 16) != 0) {
                  q = ipv6;
                  inet_ntop(p->ai_family, addr, ipv6str, sizeof ipv6str);
                  printf(" => %s", ipv6str);
                }
              } else if (p->ai_family == AF_INET) {
                ipv4 = (struct sockaddr_in *)p->ai_addr;
                addr4 = &(ipv4->sin_addr);
                if (q4 == NULL ||
                    memcmp(&ipv4->sin_addr, &q4->sin_addr, 4) != 0) {
                  q4 = ipv4;
                  inet_ntop(p->ai_family, addr4, ipv4str, sizeof ipv4str);
                  printf(" => %s", ipv4str);
                }
              }
            }
            printf("\n");
            freeaddrinfo(res);  // free the linked list
          } else
            printf("Found: %s\n", nexthost);
        } else
          printf("Found: %s\n", nexthost);
        cnt++;
        errcnt = 0;
      }
    } else
      ok = 0;

    if (ok == 0) {
      for (i = 0; i < len; i++) {
        if (i % 16 == 0) printf(" ");
        if (i % 8 == 0) printf(" ");
        printf("%02x ", buf2[i]);
        if (i % 16 == 15) printf("\n");
      }
      printf("\n");
    }
  }
  if (ok == 2) printf("Done, %d entries found.\n", cnt);

  close(sock);
  if (ok == 2)
    return 0;
  else
    return -1;
}
