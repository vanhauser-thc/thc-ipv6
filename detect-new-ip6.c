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

unsigned char *pkt = NULL, *dstmac, *dst;
int            pkt_len = 0;
int            mychecksum;
char *         interface, *script = NULL, es[300];
char *         ptr3, *ptr4;
int            i;

void help(char *prg) {
  printf("%s %s (c) 2020 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf("Syntax: %s interface [script]\n\n", prg);
  printf("This tools detects new IPv6 addresses joining the local network.\n");
  printf(
      "If script is supplied, it is executed with the detected IPv6 address as "
      "first\nand the interface as second command line option.\n\n");
  exit(-1);
}

void intercept(u_char *foo, const struct pcap_pkthdr *header,
               const unsigned char *data) {
  unsigned char *ipv6hdr = (unsigned char *)(data + 14);
  int            len = header->caplen - 14;

  if (do_hdr_size) {
    ipv6hdr = (unsigned char *)(data + do_hdr_size);
    len = header->caplen - do_hdr_size;
    if ((ipv6hdr[0] & 240) != 0x60) return;
  }

  if (debug) {
    printf("DEBUG: packet received\n");
    thc_dump_data((unsigned char *)data, header->caplen, "Received Packet");
  }
  if (ipv6hdr[6] != NXT_ICMP6 || ipv6hdr[40] != ICMP6_NEIGHBORSOL || len < 64)
    return;
  if (*(ipv6hdr + 8) + *(ipv6hdr + 9) + *(ipv6hdr + 10) + *(ipv6hdr + 11) +
          *(ipv6hdr + 12) + *(ipv6hdr + 13) + *(ipv6hdr + 14) +
          *(ipv6hdr + 15) !=
      0)
    return;
  if (debug)
    printf(
        "DEBUG: packet is a valid duplicate ip6 check via icmp6 neighbor "
        "solitication\n");

  (void)wait3(NULL, WNOHANG, NULL);
  ptr4 = thc_ipv62notation((char *)(ipv6hdr + 48));
  printf("Detected new ip6 address: %s\n", ptr4);

  if (script != NULL && fork() == 0) {
    snprintf(es, sizeof(es), "%s %s %s", script, ptr4, interface);
    if (system(es) < 0) fprintf(stderr, "Error: Executing failed - %s\n", es);
    exit(0);
  }

  free(ptr4);
  return;
}

int main(int argc, char *argv[]) {
  if (argc < 2 || strncmp(argv[1], "-h", 2) == 0) help(argv[0]);

  interface = argv[1];
  if (argc > 2) script = argv[2];

  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  printf("Started ICMP6 DAD detection (Press Control-C to end) ...\n");
  return thc_pcap_function(interface, "icmp6", (char *)intercept, 1, NULL);
}
