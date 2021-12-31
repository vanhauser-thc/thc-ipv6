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

int rawmode = 0;
int empty = 0;

void help(char *prg) {
  printf("%s %s (c) 2022 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf(
      "Syntax: %s [-l] interface advertise|solicitate|terminate [own-ip "
      "[own-mac-address]]\n\n",
      prg);
  printf("Announce, delete or soliciated MLD router - sourself or others.\n");
  printf(
      "Use -l to loop and send (in 5s intervals) until Control-C is "
      "pressed.\n");
  //  printf("Use -r to use raw mode.\n\n");
  exit(-1);
}

void check_packets(u_char *foo, const struct pcap_pkthdr *header,
                   const unsigned char *data) {
  unsigned char *ptr = (unsigned char *)data;
  int            len = header->caplen;

  if (rawmode == 0) {
    if (do_hdr_size) {
      ptr += do_hdr_size;
      len -= do_hdr_size;
      if ((ptr[0] & 240) != 0x60) return;
    } else {
      ptr += 14;
      len -= 14;
    }
  }
  if (debug) thc_dump_data(ptr, len, "Received Packet");
  if (len > 43 && ptr[6] == 0x3a && ptr[40] == ICMP6_MLD_ROUTERADV)
    printf("MLD router advertisement: %s is performing MLD routing\n",
           thc_ipv62notation(ptr + 8));
}

int main(int argc, char *argv[]) {
  unsigned char *pkt1 = NULL, buf[4];
  unsigned char *dst6 = thc_resolve6("ff02:0:0:0:0:0:0:6a"), *src6 = NULL,
                srcmac[16] = "", *mac = srcmac;
  int     pkt1_len = 0;
  char *  interface, string[64] = "icmp6";
  int     ttl = 1, mode = 0, wait1 = 0, wait2 = 0, loop = 0;
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
  if (strncasecmp(argv[2], "sol", 3) == 0 ||
      strncasecmp(argv[2], "que", 3) == 0)
    mode = ICMP6_MLD_ROUTERSOL;
  if (strncasecmp(argv[2], "ad", 2) == 0) {
    mode = ICMP6_MLD_ROUTERADV;
    wait1 = 15;
    wait2 = 0x00300006;
  }
  if (strncasecmp(argv[2], "ter", 3) == 0 ||
      strncasecmp(argv[2], "del", 3) == 0)
    mode = ICMP6_MLD_ROUTERTERMINATION;

  if (mode == 0) {
    fprintf(
        stderr,
        "Error: no mode defined, specify solitate, advertise or terminate\n");
    exit(-1);
  }

  if (argc < 4 || argv[3] == NULL || argv[3][0] == 0)
    src6 = thc_get_own_ipv6(interface, dst6, PREFER_LINK);
  else
    src6 = thc_resolve6(argv[3]);

  if (argc == 5 && argv[4] != NULL && argv[4][0] != 0)
    sscanf(argv[4], "%x:%x:%x:%x:%x:%x", (unsigned int *)&srcmac[0],
           (unsigned int *)&srcmac[1], (unsigned int *)&srcmac[2],
           (unsigned int *)&srcmac[3], (unsigned int *)&srcmac[4],
           (unsigned int *)&srcmac[5]);
  else
    mac = thc_get_own_mac(interface);

  if ((p = thc_pcap_init(interface, string)) == NULL) {
    fprintf(stderr, "Error: could not capture on interface %s with string %s\n",
            interface, string);
    exit(-1);
  }

  if ((pkt1 = thc_create_ipv6_extended(interface, PREFER_LINK, &pkt1_len, src6,
                                       dst6, ttl, 0, 0, 0, 0)) == NULL)
    return -1;
  if (thc_add_icmp6(pkt1, &pkt1_len, mode, wait1 % 256, wait2,
                    (unsigned char *)&buf, 0, 0) < 0)
    return -1;
  if (thc_generate_pkt(interface, mac, NULL, pkt1, &pkt1_len) < 0) {
    fprintf(stderr, "Error: Can not generate packet, exiting ...\n");
    exit(-1);
  }

  printf("Sending packet%s to %s%s\n", loop ? "s" : "", argv[2],
         loop ? " (Press Control-C to end)" : "");
  do {
    thc_send_pkt(interface, pkt1, &pkt1_len);
    sleep(5);
    if (mode == ICMP6_MLD_ROUTERSOL)
      while (thc_pcap_check(p, (char *)check_packets, NULL))
        ;
  } while (loop);
  return 0;  // never reached
}
