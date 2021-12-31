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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "thc-ipv6.h"

void help(char *prg) {
  printf("%s %s (c) 2022 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf(
      "Syntax: %s [-FHD] [-m srcmac] [-s src6] [-p srcport] interface "
      "ipv6-to-ipv4-gateway ipv4-src ipv4-dst [port]\n\n",
      prg);
  printf("Options:\n");
  printf(
      "  -F         insert atomic fragment header (can be set multiple "
      "times)\n");
  printf("  -H         insert and empty hop-by-hop header\n");
  printf(
      "  -D         insert a large destination header that fragments the "
      "packet\n");
  printf("  -p srcport  set a specific UDP source port or Ping ID\n");
  printf("  -s src6    set a specific IPv6 source address\n");
  printf("  -m srcmac  set a specific MAC source address\n");
  printf(
      "\nSend an IPv4 packet to an IPv6 4to6 gateway. If a port is specified, "
      "a UDP packet is sent, otherwise an ICMPv4 ping.\n");

  exit(-1);
}

int main(int argc, char *argv[]) {
  unsigned char *pkt1 = NULL, buf2[6], buf3[1500];
  unsigned char *gateway6, *src6 = NULL, *dst6 = NULL, srcmac[16] = "",
                           *mac = NULL;
  int pkt1_len = 0, prefer = PREFER_GLOBAL, i, do_hop = 0, do_dst = 0,
      do_frag = 0, cnt, type = NXT_ICMP6, offset = 14;
  char *        interface;
  thc_ipv6_hdr *hdr;
  int           src4 = 0, dst4 = 0, port = -1, sport = 10240 + getpid() % 10240;

  if (argc < 5 || strncmp(argv[1], "-h", 2) == 0) help(argv[0]);

  if (getenv("THC_IPV6_PPPOE") != NULL || getenv("THC_IPV6_6IN4") != NULL)
    printf("WARNING: %s is not working with injection!\n", argv[0]);

  while ((i = getopt(argc, argv, "DFHs:m:p:")) >= 0) {
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
      case 'm':
        mac = srcmac;
        sscanf(optarg, "%x:%x:%x:%x:%x:%x", (unsigned int *)&mac[0],
               (unsigned int *)&mac[1], (unsigned int *)&mac[2],
               (unsigned int *)&mac[3], (unsigned int *)&mac[4],
               (unsigned int *)&mac[5]);
        break;
      case 's':
        if ((src6 = thc_resolve6(optarg)) == NULL) {
          fprintf(stderr, "Error: invalid IPv6 source address specified: %s\n",
                  optarg);
        }
        break;
      case 'p':
        sport = atoi(optarg);
        break;
      default:
        fprintf(stderr, "Error: invalid option %c\n", i);
        exit(-1);
    }
  }

  if (argc - optind < 4) help(argv[0]);

  if (do_hdr_size) offset = do_hdr_size;
  interface = argv[optind];
  if ((gateway6 = thc_resolve6(argv[optind + 1])) == NULL) {
    fprintf(stderr, "Error: %s does not resolve to a valid IPv6 address\n",
            argv[optind + 1]);
    exit(-1);
  }

  // src ip4, dst ip4
  if (inet_aton(argv[optind + 2], (struct in_addr *)&src4) < 0) {
    fprintf(stderr, "Error: not a valid IPv4 address: %s\n", argv[optind + 2]);
    exit(-1);
  }
  if (inet_aton(argv[optind + 3], (struct in_addr *)&dst4) < 0) {
    fprintf(stderr, "Error: not a valid IPv4 address: %s\n", argv[optind + 3]);
    exit(-1);
  }

  if (argc - optind > 4) port = atoi(argv[optind + 4]);

  if (mac == NULL) {
    if ((mac = thc_get_own_mac(interface)) == NULL) {
      fprintf(stderr, "Error: invalid interface %s\n", interface);
      exit(-1);
    }
  }

  if ((pkt1 = thc_create_ipv6_extended(interface, prefer, &pkt1_len, src6,
                                       gateway6, 64, 0, 0, 0, 0)) == NULL)
    return -1;
  if (do_hop) {
    type = NXT_HBH;
    if (thc_add_hdr_hopbyhop(pkt1, &pkt1_len, buf2, sizeof(buf2)) < 0)
      return -1;
  }
  if (do_frag) {
    if (type == NXT_ICMP6) type = NXT_FRAG;
    for (i = 0; i <= do_frag; i++)
      if (thc_add_hdr_oneshotfragment(pkt1, &pkt1_len, cnt++) < 0) return -1;
  }
  if (do_dst) {
    if (type == NXT_ICMP6) type = NXT_DST;
    if (thc_add_hdr_dst(pkt1, &pkt1_len, buf3, sizeof(buf3)) < 0) return -1;
  }
  if (thc_add_ipv4_rudimentary(pkt1, &pkt1_len, src4, dst4, sport, port) < 0)
    return -1;
  if (thc_generate_pkt(interface, mac, NULL, pkt1, &pkt1_len) < 0) {
    fprintf(stderr, "Error: Can not generate packet, exiting ...\n");
    exit(-1);
  }

  printf("Sending IPv4 %s packet from %s to %s via 4to6 gateway %s\n",
         port == -1 ? "ICMPv4 ping" : "UDPv4", argv[optind + 2],
         argv[optind + 3], argv[optind + 1]);
  if (do_dst) {
    hdr = (thc_ipv6_hdr *)pkt1;
    thc_send_as_fragment6(interface, src6, dst6, type, hdr->pkt + 40 + offset,
                          hdr->pkt_len - 40 - offset, 1240);
  } else {
    thc_send_pkt(interface, pkt1, &pkt1_len);
  }

  return 0;
}
