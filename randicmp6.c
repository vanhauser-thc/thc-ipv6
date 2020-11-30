#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <time.h>
#include <pcap.h>
#include "thc-ipv6.h"

void check_packet(u_char *foo, const struct pcap_pkthdr *header,
                  const unsigned char *data) {
  unsigned char *ipv6hdr = (unsigned char *)(data + 14);
  int            len = header->caplen - 14;

  if (do_hdr_size) {
    ipv6hdr = (unsigned char *)(data + do_hdr_size);
    len -= (do_hdr_size - 14);
    if ((ipv6hdr[0] & 240) != 0x60 || ipv6hdr[6] != NXT_ICMP6 || len < 48)
      return;
  } else if (len < 48)
    return;

  printf("Received type %d code %d\n", ipv6hdr[40], ipv6hdr[41]);
}

int main(int argc, char *argv[]) {
  unsigned char *dst61, *src61 = NULL;
  unsigned char  buf[8];
  int            pkt_len = 600;
  char *         interface, string[64];
  unsigned char *pkt = NULL;
  unsigned char *srcmac, *dstmac;  // can define as null to auto generate
  int     type, code, flags = 0, tf = 0, tt = 255, cf = 0, ct = 255, print = 1;
  pcap_t *p;

  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  if (argc < 3) {
    printf(
        "Syntax: %s [-p] [-s sourceip] interface destination [type [code]]\n\n",
        argv[0]);
    printf("Sends all ICMPv6 type and code combinations to destination.\n");
    printf("Option -s  sets the source IPv6 address.\n");
    printf("Option -p  will not print answers received.\n");
    exit(0);
  }

  if (strncmp(argv[1], "-p", 2) == 0) {
    print = 0;
    argv++;
    argc--;
  }
  if (strncmp(argv[1], "-s", 2) == 0) {
    src61 = thc_resolve6(argv[2]);
    argv++;
    argv++;
    argc--;
    argc--;
  }
  if (strncmp(argv[1], "-p", 2) == 0) {
    print = 0;
    argv++;
    argc--;
  }

  interface = argv[1];
  // source and destination IPv6 addresses
  dst61 = thc_resolve6(argv[2]);
  if (src61 == NULL) src61 = thc_get_own_ipv6(interface, dst61, PREFER_GLOBAL);

  if (argc >= 4) tf = tt = atoi(argv[3]);
  if (argc >= 5) cf = ct = atoi(argv[4]);

  memset(buf, 0, sizeof(buf));
  printf("Sending ICMPv6 Packets to %s%%%s\n", argv[2], argv[1]);

  srcmac = thc_get_own_mac(interface);
  dstmac = thc_get_mac(interface, src61, dst61);

  if (srcmac == NULL) {
    fprintf(stderr, "Error: illegal interface: %s\n", interface);
    exit(-1);
  }
  if (dstmac == NULL) {
    fprintf(stderr, "Error: can not resolve target: %s\n", argv[2]);
    exit(-1);
  }

  if (dst61[0] == 0xff) {
    sprintf(string, "icmp6 and dst %s", thc_ipv62notation(src61));
  } else {
    sprintf(string, "icmp6 and src %s", thc_ipv62notation(dst61));
  }

  if ((p = thc_pcap_init(interface, string)) == NULL) {
    fprintf(stderr, "Error: could not capture on interface %s with string %s\n",
            interface, string);
    exit(-1);
  }

  for (type = tf; type <= tt; type++) {
    printf("Sending ICMPv6 type %d ...\n", type);
    for (code = cf; code <= ct; code++) {
      // build the packet
      if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                          src61, dst61, 255, 0, 0, 0, 0)) ==
          NULL)
        printf("Packet Creation Failed\n");

      // add icmp part
      if (thc_add_icmp6(pkt, &pkt_len, type, code, flags, buf, sizeof(buf), 0) <
          0)
        return -1;

      // generate packet
      if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0) {
        printf("generate failed\n");
        return -1;
      }
      // send the packet out
      if (thc_send_pkt(interface, pkt, &pkt_len) < 0)
        printf("packet not sent \n");

      thc_destroy_packet(pkt);  // destroy the packet
      pkt = NULL;
      pkt_len = 0;
      if (print) {
        usleep(5000);
        while (thc_pcap_check(p, (char *)check_packet, NULL) > 0)
          ;
      }
    }
  }
  if (print) {
    sleep(1);
    while (thc_pcap_check(p, (char *)check_packet, NULL) > 0)
      ;
  }
  printf("Done!\n");
  return 0;
}
