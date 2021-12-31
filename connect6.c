#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include "thc-ipv6.h"

#define PROGRAM "connect6"

#ifndef _BSD_SOURCE
struct in6_pktinfo {
  struct in6_addr ipi6_addr;
  int             ipi6_ifindex;
};
#endif
char *prg;

void help() {
  printf("%s %s (c) 2022 by %s %s\n\n", PROGRAM, VERSION, AUTHOR, RESOURCE);
  printf("Syntax: %s [-a | -A type] [-i] target-ip target-port\n\n", prg);
  printf("Options:\n");
  printf("  -a       send Hop-by-Hop Router Alert option\n");
  printf("  -A type  like -a but lets you define the alarmtype (number)\n");
  printf("  -i       interactive mode (like telnet)\n");
  printf("  -I       end a linefeed, wait for a string, print it\n");
  printf("  -O       try TCP Fast Open connection\n");
  printf("  -w ms    wait time for connect in ms (default: 1000)\n");
  printf("  -p       ping mode\n");
  printf("You can supply a %%interface identifier to the target-ip\n");
  printf("Returns 0 on successful connect, 1 on timeout/reset\n");
  exit(-1);
}

void myalarm(int signal) {
  return;
}

int main(int argc, char *argv[]) {
  int i, t = -1, conn_len, do_alert = 0, interactive = 0, optval, optlen,
         fastopen = 0;
  unsigned long int   ping = 0, waitms = 1000;
  char                buf[1033], *interface, *target;
  struct addrinfo *   res, *aip, *aip_saved = NULL;
  struct addrinfo     hints;
  struct sockaddr_in6 conn;
  unsigned short      rtalert_code =
      0;  // alert type, 0 = MLD, 1 = RSVP, 2 = Active Network

  prg = argv[0];
  if (argc < 3 || strncmp(argv[1], "-h", 2) == 0 ||
      strncmp(argv[1], "--h", 3) == 0)
    help();

  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  signal(SIGALRM, myalarm);

  if (getenv("THC_IPV6_PPPOE") != NULL || getenv("THC_IPV6_6IN4") != NULL)
    printf("WARNING: %s is not working with injection!\n", argv[0]);

  while ((i = getopt(argc, argv, "paA:iIOw:")) >= 0) {
    switch (i) {
      case 'w':
        waitms = atoi(optarg);
      case 'p':
        ping = 1;
        break;
      case 'a':
        do_alert = 1;
        break;
      case 'O':
        fastopen = 1;
        break;
      case 'A':
        do_alert = 1;
        rtalert_code = atoi(optarg);
        break;
      case 'i':
        interactive = 1;
        break;
      case 'I':
        interactive = 2;
        break;
      default:
        fprintf(stderr, "Error: invalid option %c\n", i);
        exit(-1);
    }
  }

  memset((char *)&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_family = AF_INET6;

  target = argv[optind];
  if ((interface = index(target, '%')) != NULL)
#ifdef SO_BINDTODEVICE
    *interface++ = 0;
#else
  {
    fprintf(stderr,
            "Error: your operating system does not support SO_BINDTODEVICE, so "
            "I can't bind to an interface!\n");
    exit(-1);
  }
#endif
  else if (strncmp(target, "fe80", 4) == 0) {
    fprintf(stderr,
            "Error: to connect to an fe80:: link local address, you must "
            "specify an interface, e.g. fe80::1%%eth0\n");
    exit(-1);
  }

  if ((i = getaddrinfo(target, argv[optind + 1], &hints, &res)) != 0) {
    fprintf(stderr, "Error: %s\n", gai_strerror(i));
    return -1;
  }

  conn_len = sizeof(conn);

  for (aip = res; aip != NULL; aip = aip->ai_next) {
    if (t == -1) {
      t = socket(aip->ai_family, aip->ai_socktype, aip->ai_protocol);
      if (t == -1) {
        perror("socket");
        freeaddrinfo(res);
        return (-1);
      }
#ifdef SO_BINDTODEVICE
      if (interface != NULL)
        if (setsockopt(t, SOL_SOCKET, SO_BINDTODEVICE, interface,
                       strlen(interface) + 1) < 0)
          fprintf(stderr, "Warning: could not bind to device %s\n", interface);
#endif
      memset(buf, 0, 8);
      if (do_alert) {
        buf[2] = 5;
        buf[3] = 2;
        buf[4] = rtalert_code / 256;
        buf[5] = rtalert_code % 256;
        if (setsockopt(t, IPPROTO_IPV6, IPV6_HOPOPTS, buf, 8) != 0) {
          perror("setsockopt");
          if (ping == 0) exit(-1);
        }
      }
      if (fastopen) {
        printf("go\n");
        if (sendto(t, buf, 0, 0, aip->ai_addr, aip->ai_addrlen) < 0) {
          printf("error!\n");
          perror("sendto");
          (void)close(t);
          t = -1;
          continue;
        }
        printf("done\n");
      } else {
        if (waitms < 2000)
          alarm(2);
        else
          alarm(waitms / 1000);
        if (connect(t, aip->ai_addr, aip->ai_addrlen) == -1) {
          perror("connect");
          (void)close(t);
          t = -1;
          continue;
        } else
          aip_saved = aip;
        alarm(0);
      }
      break;
    }
  }

  if (t < 0) {
    fprintf(stderr, "Error: can not connect to target\n");
    exit(1);
  }

  if (ping == 0) {
    printf("Connected.\n");

    i = getsockopt(t, IPPROTO_IPV6, IPV6_MTU, &optval, &optlen);
    printf("MTU to target is %d (return code from getsockopt was %d)\n", optval,
           i);
    if (interactive == 1) {
      fcntl(fileno(stdin), F_SETFL, O_NONBLOCK);
      fcntl(t, F_SETFL, O_NONBLOCK);
      while (1) {
        if ((i = recv(t, buf, sizeof(buf), 0)) > 0) fwrite(buf, 1, i, stdout);
        if ((i = read(fileno(stdin), buf, sizeof(buf))) > 0) send(t, buf, i, 0);
        usleep(10);
      }
    } else if (interactive == 2) {
      snprintf(buf, sizeof(buf), "\r\n");  // do something else than enter maybe
      send(t, buf, strlen(buf), 0);
      alarm(3);
      if ((i = recv(t, buf, sizeof(buf), 0)) < 0) {
        close(t);
        return 0;
      }
      printf("%s\n", buf);
    }
  } else {
    fd_set            myset;
    struct timeval    tv;
    unsigned long int diff;

    close(t);
    printf("Connected seq=%lu\n", ping);
    while (1) {
      if ((t = socket(aip_saved->ai_family, aip_saved->ai_socktype,
                      aip_saved->ai_protocol)) >= 0) {
#ifdef SO_BINDTODEVICE
        if (interface != NULL)
          if (setsockopt(t, SOL_SOCKET, SO_BINDTODEVICE, interface,
                         strlen(interface) + 1) < 0)
            fprintf(stderr, "Warning: could not bind to device %s\n",
                    interface);
#endif
        memset(buf, 0, 8);
        if (do_alert) {
          buf[2] = 5;
          buf[3] = 2;
          buf[4] = rtalert_code / 256;
          buf[5] = rtalert_code % 256;
          if (setsockopt(t, IPPROTO_IPV6, IPV6_HOPOPTS, buf, 8) != 0)
            perror("setsockopt");
        }
        fcntl(t, F_SETFL, O_NONBLOCK);
        ping++;
        connect(t, aip->ai_addr, aip->ai_addrlen);
        FD_ZERO(&myset);
        FD_SET(t, &myset);
        tv.tv_sec = waitms / 1000;
        tv.tv_usec = (waitms % 1000) * 1000;
        if (select(t + 1, NULL, &myset, NULL, &tv) > 0) {
          diff = (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
          printf("Connected seq=%lu %lus %lums\n", ping, (waitms - diff) / 1000,
                 (waitms - diff) % 1000);
        }
        // wait for rest of timeout
        close(t);
        select(t + 1, NULL, NULL, NULL, &tv);
      }
    }
  }
  return 0;
}
