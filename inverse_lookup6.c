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

int           rawmode = 0;
unsigned char dmac[6], *mac;
int           done = 0;

void help(char *prg) {
  printf("%s %s (c) 2022 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf("Syntax: %s interface mac-address\n\n", prg);
  printf(
      "Performs an inverse address query, to get the IPv6 addresses that are "
      "assigned\n");
  printf("to a MAC address. Note that only few systems support this yet.\n");
  exit(-1);
}

void check_packets(u_char *foo, const struct pcap_pkthdr *header,
                   const unsigned char *data) {
  unsigned char *ptr = (unsigned char *)data, *orig_ptr;
  int            len = header->caplen, i, j;

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

  orig_ptr = ptr;
  if (debug) thc_dump_data(ptr, len, "Received Packet");
  if (ptr[6] == 0x3a && ptr[40] == ICMP6_INVNEIGHBORADV && len >= 56) {
    done = 1;
    j = (len - 56) / 16;
    if (j <= 0) {
      printf("Empty Inverse Neighbor Discovery message received by %s for %s\n",
             thc_ipv62notation((char *)ptr + 8), mac);
    } else {
      ptr += 48;
      len -= 48;
      while (len > 15) {
        if (*ptr == 10) {
          ptr++;
          j = ((*ptr * 8) - 8) / 16;
          printf(
              "Inverse Advertisement Discovery message received by %s for %s "
              "(%d entries):\n",
              thc_ipv62notation((char *)orig_ptr + 8), mac, j);
          if (j >= 1)
            for (i = 0; i < j; i++)
              printf("  %s\n", thc_ipv62notation((char *)ptr + 7 + i * 16));
        } else
          ptr++;
        len -= *ptr * 8 - 1;
        ptr += *ptr * 8 - 1;
      }
    }
  }
}

int main(int argc, char *argv[]) {
  unsigned char *pkt1 = NULL, buf[24];
  unsigned char *dst6 = NULL, *smac, dstmac[16] = "", *dmac = dstmac;
  int            pkt1_len = 0;
  char *         interface, string[64] = "icmp6";
  pcap_t *       p;

  memset(buf, 0, sizeof(buf));

  if (argc != 3 || strncmp(argv[1], "-h", 2) == 0) help(argv[0]);

  if (getenv("THC_IPV6_PPPOE") != NULL || getenv("THC_IPV6_6IN4") != NULL)
    printf("WARNING: %s is not working with injection!\n", argv[0]);

  interface = argv[1];

  sscanf(argv[2], "%x:%x:%x:%x:%x:%x", (unsigned int *)&dmac[0],
         (unsigned int *)&dmac[1], (unsigned int *)&dmac[2],
         (unsigned int *)&dmac[3], (unsigned int *)&dmac[4],
         (unsigned int *)&dmac[5]);

  mac = argv[2];
  if ((smac = thc_get_own_mac(interface)) == NULL) {
    fprintf(stderr, "Error: invalid interface %s\n", interface);
    exit(-1);
  }
  dst6 = thc_resolve6("ff02::1");

  if ((pkt1 = thc_create_ipv6_extended(interface, PREFER_LINK, &pkt1_len, NULL,
                                       dst6, 255, 0, 0, 0, 0)) == NULL)
    return -1;
  memset(buf, 0, sizeof(buf));
  buf[0] = 0x01;
  buf[1] = 0x01;
  memcpy(buf + 2, smac, 6);
  buf[8] = 0x02;
  buf[9] = 0x01;
  memcpy(buf + 10, dmac, 6);
  if (thc_add_icmp6(pkt1, &pkt1_len, ICMP6_INVNEIGHBORSOL, 0, 0,
                    (unsigned char *)&buf, 16, 0) < 0)
    return -1;
  if (thc_generate_pkt(interface, smac, dmac, pkt1, &pkt1_len) < 0) {
    fprintf(stderr, "Error: Can not generate packet, exiting ...\n");
    exit(-1);
  }

  if ((p = thc_pcap_init(interface, string)) == NULL) {
    fprintf(stderr, "Error: could not capture on interface %s with string %s\n",
            interface, string);
    exit(-1);
  }
  printf("Sending inverse packet for %s\n", argv[1]);
  thc_send_pkt(interface, pkt1, &pkt1_len);
  sleep(1);
  while (thc_pcap_check(p, (char *)check_packets, NULL))
    ;
  return 0;  // never reached
}
