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

int   rawmode = 0;
char *multicast6 = NULL;
int   empty = 0;

void help(char *prg) {
  printf("%s %s (c) 2022 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf(
      "Syntax: %s [-l] interface add|delete|query [multicast-address [ttl "
      "[own-ip [own-mac-address [destination-mac-address]]]]]\n\n",
      prg);
  printf(
      "Ad(d)vertise or delete yourself - or anyone you want - in a multicast "
      "group of your choice\n");
  printf("Query ask on the network who is listening to multicast addresses\n");
  printf(
      "Use -l to loop and send (in 5s intervals) until Control-C is "
      "pressed.\n");
  //  printf("Use -r to use raw mode.\n\n");
  exit(-1);
}

void check_packets(u_char *foo, const struct pcap_pkthdr *header,
                   const unsigned char *data) {
  unsigned char *ptr = (unsigned char *)data, len = header->caplen - 14;

  if (rawmode == 0) ptr += 14;
  if (do_hdr_size) {
    ptr += (do_hdr_size - 14);
    len -= (do_hdr_size - 14);
    if ((ptr[0] & 240) != 0x60) return;
  }
  if (debug) thc_dump_data(ptr, len, "Received Packet");
  if (ptr[6] == 0 && ptr[40] == 0x3a && ptr[41] == 0 && ptr[42] == 5 &&
      ptr[48] == ICMP6_MLD_REPORT && len >= 72)
    if (empty == 1 || memcmp(multicast6, ptr + 56, 16) == 0)
      printf("MLD Report: %s is listening on %s\n", thc_ipv62notation(ptr + 8),
             thc_ipv62notation(ptr + 56));
}

int main(int argc, char *argv[]) {
  unsigned char *pkt1 = NULL, buf[24];
  unsigned char *dst6 = NULL, *src6 = NULL, srcmac[16] = "", *mac = srcmac,
                dstmac[16] = "", *dmac = dstmac;
  int     pkt1_len = 0, i = 0, j;
  char *  interface, string[64] = "ip6 and not udp and not tcp";
  int     ttl = 1, mode = 0, wait = 0, loop = 0;
  pcap_t *p;

  memset(buf, 0, sizeof(buf));

  if (argc > 1 && argv[0] != NULL && strcmp(argv[1], "-r") == 0) {
    thc_ipv6_rawmode(1);
    rawmode = 1;
    argv++;
    argc--;
  }
  if (argc > 1 && argv[0] != NULL && strcmp(argv[1], "-l") == 0) {
    loop = 1;
    argv++;
    argc--;
  }
  if (argc > 1 && argv[0] != NULL && strcmp(argv[1], "-r") == 0) {
    thc_ipv6_rawmode(1);
    rawmode = 1;
    argv++;
    argc--;
  }

  if (argc < 3 || strncmp(argv[1], "-h", 2) == 0) help(argv[0]);

  interface = argv[1];
  if (strncasecmp(argv[2], "add", 3) == 0) mode = ICMP6_MLD_REPORT;
  if (strncasecmp(argv[2], "del", 3) == 0) mode = ICMP6_MLD_DONE;
  if (strncasecmp(argv[2], "que", 3) == 0) {
    mode = ICMP6_MLD_QUERY;
    wait = 0x0444 << 16;
  }
  if (mode == 0) {
    fprintf(stderr, "Error: no mode defined, specify add, delete or query\n");
    exit(-1);
  }
  if (argc == 3 || argv[3] == NULL || argv[3][0] == 0) {
    multicast6 = thc_resolve6("::");
    empty = 1;
  } else {
    if ((multicast6 = thc_resolve6(argv[3])) == NULL) {
      fprintf(stderr, "Error: %s does not resolve to a valid IPv6 address\n",
              argv[3]);
      exit(-1);
    }

    for (j = 0; j < 16; j++)
      i += multicast6[j];
    if (i == 0) empty = 1;
  }
  if (mode == ICMP6_MLD_QUERY) {
    if (memcmp(multicast6, buf, 16))
      dst6 = multicast6;
    else
      dst6 = thc_resolve6("ff02::1");
  } else
    dst6 = thc_resolve6("ff02::2");
  if (argv[5] != NULL && argc > 5) ttl = atoi(argv[5]);
  if (argv[6] != NULL && argc > 6)
    src6 = thc_resolve6(argv[6]);
  else
    src6 = thc_get_own_ipv6(interface, dst6, PREFER_LINK);
  if (rawmode == 0) {
    if (argv[7] != NULL && argc > 7)
      sscanf(argv[7], "%x:%x:%x:%x:%x:%x", (unsigned int *)&srcmac[0],
             (unsigned int *)&srcmac[1], (unsigned int *)&srcmac[2],
             (unsigned int *)&srcmac[3], (unsigned int *)&srcmac[4],
             (unsigned int *)&srcmac[5]);
    else
      mac = thc_get_own_mac(interface);
    if (argv[8] != NULL && argc > 8)
      sscanf(argv[8], "%x:%x:%x:%x:%x:%x", (unsigned int *)&dstmac[0],
             (unsigned int *)&dstmac[1], (unsigned int *)&dstmac[2],
             (unsigned int *)&dstmac[3], (unsigned int *)&dstmac[4],
             (unsigned int *)&dstmac[5]);
    else
      dmac = NULL;
  }

  if ((p = thc_pcap_init_promisc(interface, string)) == NULL) {
    fprintf(stderr, "Error: could not capture on interface %s with string %s\n",
            interface, string);
    exit(-1);
  }

  if ((pkt1 = thc_create_ipv6_extended(interface, PREFER_LINK, &pkt1_len, src6,
                                       dst6, ttl, 0, 0, 0, 0)) == NULL)
    return -1;
  memset(buf, 0, sizeof(buf));
  buf[0] = 5;
  buf[1] = 2;
  if (thc_add_hdr_hopbyhop(pkt1, &pkt1_len, buf, 6) < 0) return -1;
  memset(buf, 0, sizeof(buf));
  memcpy(buf, multicast6, 16);
  if (thc_add_icmp6(pkt1, &pkt1_len, mode, 0, wait, (unsigned char *)&buf, 16,
                    0) < 0)
    return -1;
  if (thc_generate_pkt(interface, mac, dmac, pkt1, &pkt1_len) < 0) {
    fprintf(stderr, "Error: Can not generate packet, exiting ...\n");
    exit(-1);
  }

  printf("Sending packet%s for %s%s\n", loop ? "s" : "", empty ? "::" : argv[3],
         loop ? " (Press Control-C to end)" : "");
  do {
    thc_send_pkt(interface, pkt1, &pkt1_len);
    if (mode == ICMP6_MLD_QUERY) {
      sleep(5);
      while (thc_pcap_check(p, (char *)check_packets, NULL))
        ;
    }
  } while (loop);
  return 0;  // never reached
}
