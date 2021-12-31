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

#define MAX_SEEN 255

char *frbuf, *frbuf2, *frint, buf3[1504];
int frbuflen, frbuf2len, do_hop = 0, do_frag = 0, do_dst = 0, type = NXT_ICMP6,
                         seen_cnt = 0;
unsigned char *frip6, *frmac, *frdst;
thc_ipv6_hdr * frhdr = NULL;
char           seen[MAX_SEEN + 1][16];
extern int     do_hdr_size;

void help(char *prg) {
  printf("%s %s (c) 2022 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf("Syntax: %s interface [target]\n\n", prg);
  printf("Dumps all local routers and their information\n\n");
  //  printf("Use -r to use raw mode.\n\n");
  exit(-1);
}

void dump_ra_reply(u_char *foo, const struct pcap_pkthdr *header,
                   const unsigned char *data) {
  unsigned char *ipv6hdr = (unsigned char *)(data + 14), *ptr, *ptr2,
                tmpbuf[16];
  int i, k, len = header->caplen - 14;

  if (do_hdr_size > 0) {
    ipv6hdr = (unsigned char *)(data + do_hdr_size);
    len -= (do_hdr_size - 14);
    if ((ipv6hdr[0] & 240) != 0x60) return;
  }

  if (ipv6hdr[6] != NXT_ICMP6 || ipv6hdr[40] != ICMP6_ROUTERADV ||
      len < 40 + 16)
    return;

  if (seen > 0) {
    for (i = 0; i < seen_cnt; i++)
      if (memcmp(seen[i], ipv6hdr + 8, 16) == 0) return;
  }
  if (seen_cnt <= MAX_SEEN) memcpy(seen[seen_cnt++], ipv6hdr + 8, 16);

  printf("Router: %s (MAC: %02x:%02x:%02x:%02x:%02x:%02x)\n",
         thc_ipv62notation(ipv6hdr + 8), data[6], data[7], data[8], data[9],
         data[10], data[11]);
  printf("  Priority: ");
  i = ipv6hdr[45] & 24;
  switch (i) {
    case 0:
      printf("medium\n");
      break;
    case 8:
      printf("high\n");
      break;
    case 16:
      printf("reserved value\n");
      break;
    case 24:
      printf("low\n");
      break;
  }
  printf("  Hop Count: %d\n", ipv6hdr[44]);
  printf("  Lifetime: %d, Reachable: %u, Retrans: %u\n",
         (ipv6hdr[46] << 8) + ipv6hdr[47],
         (ipv6hdr[48] << 24) + (ipv6hdr[49] << 16) + (ipv6hdr[50] << 8) +
             ipv6hdr[51],
         (ipv6hdr[52] << 24) + (ipv6hdr[53] << 16) + (ipv6hdr[54] << 8) +
             ipv6hdr[55]);
  printf("  Flags: ");
  if ((ipv6hdr[45] & 128) > 0)
    printf("managed ");
  else
    printf("NOTmanaged ");
  if ((ipv6hdr[45] & 64) > 0)
    printf("other ");
  else
    printf("NOTother ");
  if ((ipv6hdr[45] & 32) > 0)
    printf("home-agent ");
  else
    printf("NOThome-agent ");
  if ((ipv6hdr[45] & 4) > 0)
    printf("proxied ");
  else
    printf("NOTproxied ");
  if ((ipv6hdr[45] & 2) > 0) printf("RESERVED-2-BIT-SET ");
  if ((ipv6hdr[45] & 1) > 0) printf("RESERVED-1-BIT-SET");
  printf("\n");
  i = len - 56;
  ptr = ipv6hdr + 56;
  printf("  Options:\n");
  while (i > 0) {
    if (i < 8 || ptr[1] * 8 > i || ptr[1] == 0) {
      printf("Packet truncated!\n\n");
      return;
    }
    // (ptr[] << 24) + (ptr[] << 16) + (ptr[] << 8) + ptr[]
    switch (*ptr) {
      case 1:
        printf("    MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", ptr[2], ptr[3],
               ptr[4], ptr[5], ptr[6], ptr[7]);
        break;
      case 3:
        if (ptr[1] != 4)
          printf("    Prefix: illegal\n");
        else {
          printf("    Prefix: %s/%d (Valid: %u, Preferred: %u)\n",
                 thc_ipv62notation(ptr + 16), ptr[2],
                 (ptr[4] << 24) + (ptr[5] << 16) + (ptr[6] << 8) + ptr[7],
                 (ptr[8] << 24) + (ptr[9] << 16) + (ptr[10] << 8) + ptr[11]);
          printf("      Flags:");
          if ((ptr[3] & 128) > 0)
            printf(" On-Link");
          else
            printf(" NOT-on-link");
          if ((ptr[3] & 64) > 0)
            printf(" Autoconfig");
          else
            printf(" NOT-autoconfig");
          if ((ptr[3] & 32) > 0)
            printf(" Router-Address");
          else
            printf(" NOT-Router-Address");
          if ((ptr[3] & 31) > 0) printf(" RESERVED-BITS-SET-%d", ptr[3] & 63);
          printf("\n");
        }
        break;
      case 5:
        printf("    MTU: %d\n",
               (ptr[4] << 24) + (ptr[5] << 16) + (ptr[6] << 8) + ptr[7]);
        break;
      case 7:
        printf("    Advertisement Interval: %d\n",
               (ptr[4] << 24) + (ptr[5] << 16) + (ptr[6] << 8) + ptr[7]);
        break;
      case 8:
        printf("    Home Agent Preference: %d %d\n", (ptr[4] << 8) + (ptr[5]),
               (ptr[6] << 8) + ptr[7]);
        break;
      case 24:
        if (ptr[1] != 3 && ptr[1] != 2)
          printf("    Route: illegal\n");
        else {
          memset(tmpbuf, 0, sizeof(tmpbuf));
          memcpy(tmpbuf, ptr + 8, 8);
          printf("    Route: %s/%d (Lifetime: %u)\n", thc_ipv62notation(tmpbuf),
                 ptr[2],
                 (ptr[4] << 24) + (ptr[5] << 16) + (ptr[6] << 8) + ptr[7]);
          printf("      Priority:");
          k = ptr[3] & 24;
          switch (k) {
            case 0:
              printf("medium\n");
              break;
            case 8:
              printf("high\n");
              break;
            case 16:
              printf("reserved value\n");
              break;
            case 24:
              printf("low\n");
              break;
          }
        }
        break;
      case 31:
        ptr2 = ptr + 9;
        while (*ptr2 != 0) {
          if (*ptr2 < 32 && *ptr2 > 0) *ptr2 = '.';
          ptr2++;
        }
        printf("    DNS Searchlist: %s (Lifetime: %u)\n", ptr + 9,
               (ptr[4] << 24) + (ptr[5] << 16) + (ptr[6] << 8) + ptr[7]);
        break;
      case 25:
        if (ptr[1] != 3)
          printf("    DNS: illegal\n");
        else {
          printf("    DNS: %s (Lifetime: %u/%u)\n", thc_ipv62notation(ptr + 8),
                 (ptr[4] << 24) + (ptr[5] << 16) + (ptr[6] << 8) + ptr[7],
                 (ptr[8] << 24) + (ptr[9] << 16) + (ptr[10] << 8) + ptr[11]);
        }
        break;
      default:
        printf("    Unknown Option Type: %d (size: %d bytes)\n", ptr[0],
               ptr[1] * 8);
    }
    i -= ptr[1] * 8;
    ptr += ptr[1] * 8;
  }

  printf("\n");
}

void clean_exit(int sig) {
  exit(0);
}

int main(int argc, char *argv[]) {
  char *         interface, string[] = "ip6 and icmp6";
  unsigned char *mac6, buf[512];
  unsigned char *dst = thc_resolve6("ff02::2"), *src = NULL;
  int            i;
  unsigned char *pkt = NULL;
  int            pkt_len = 0;
  int            rawmode = 0;
  pcap_t *       p;

  if (argc < 2 || strncmp(argv[1], "-h", 2) == 0) help(argv[0]);

  while ((i = getopt(argc, argv, "rS:h")) >= 0) {
    switch (i) {
      case 'r':
        thc_ipv6_rawmode(1);
        rawmode = 1;
        break;
      case 'h':
        help(argv[0]);
        break;
      case 'S':
        if ((src = thc_resolve6(optarg)) == NULL) {
          fprintf(stderr, "Error: could not resolve %s\n", optarg);
          return -1;
        }
      default:
        fprintf(stderr, "Error: invalid option %c\n", i);
        exit(-1);
    }
  }

  interface = argv[optind];
  if ((mac6 = thc_get_own_mac(interface)) == NULL) {
    fprintf(stderr, "Error: invalid interface %s\n", interface);
    exit(-1);
  }
  if (argc - optind > 1 && argv[optind + 1] != NULL)
    dst = thc_resolve6(argv[optind + 1]);

  memset(buf, 0, sizeof(buf));
  buf[0] = 1;
  buf[1] = 1;
  memcpy(buf + 2, mac6, 6);
  i = 8;
  memset(seen, 0, sizeof(seen));

  if ((p = thc_pcap_init(interface, string)) == NULL) {
    fprintf(stderr, "Error: could not capture on interface %s with string %s\n",
            interface, string);
    exit(-1);
  }

  if ((pkt = thc_create_ipv6_extended(interface, PREFER_LINK, &pkt_len, src,
                                      dst, 255, 0, 0, 0xe0, 0)) == NULL)
    return -1;
  if (thc_add_icmp6(pkt, &pkt_len, ICMP6_ROUTERSOL, 0, 0, buf, i, 0) < 0)
    return -1;
  if (thc_generate_and_send_pkt(interface, mac6, NULL, pkt, &pkt_len) < 0)
    return -1;

  signal(SIGALRM, clean_exit);
  alarm(5);
  while (1) {
    while (thc_pcap_check(p, (char *)dump_ra_reply, NULL) > 0)
      ;
    usleep(100);
  }
  return 0;
}
