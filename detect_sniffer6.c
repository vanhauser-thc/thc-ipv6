
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
#include <sys/timeb.h>
#include "thc-ipv6.h"

struct timespec ts, ts2;
int             found = 0, oneonly = 0;
char            doubles[256][16];

void help(char *prg) {
  printf("%s %s (c) 2020 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf("Syntax: %s interface [target6]\n\n", prg);
  printf("Tests if systems on the local LAN are sniffing.\n");
  printf("Works against Windows, Linux, OS/X and *BSD\n");
  printf(
      "If no target is given, the link-local-all-nodes address is used, "
      "which\nhowever not always works.\n");
  exit(-1);
}

void alarming() {
  if (found == 0)
    printf("No packets received, no vulnerable system seems to be sniffing.\n");
  else
    printf("%d sniffing host%s detected.\n", found, found == 1 ? "" : "s");
  exit(0);
}

void check_packets(u_char *pingdata, const struct pcap_pkthdr *header,
                   const unsigned char *data) {
  int            len = header->caplen, ok = 0, i;
  unsigned char *ptr = (unsigned char *)data;

  if (do_hdr_size) {
    len -= do_hdr_size;
    ptr += do_hdr_size;
    if ((ptr[0] & 240) != 0x60) return;
  } else {
    len -= 14;
    ptr += 14;
  }

  if (len < 136)  // ignoring too short packet
    return;
  for (i = 0; i < 8 && ok == 0; i++)
    if (memcmp(pingdata, data + 106 + i, 8) == 0) ok = 1;

  if (ok) {
    if (found) {
      for (i = 0; i < found && ok == 1; i++)
        if (memcmp(doubles[i], thc_ipv62notation(ptr + 8), 16) == 0) ok = 0;
    }
    if (ok) {
      printf(" Sniffing host detected: %s\n", thc_ipv62notation(ptr + 8));
      memcpy(doubles[found], thc_ipv62notation(ptr + 8), 16);
      found++;
      if (oneonly) alarming();
    }
  }
}

int main(int argc, char *argv[]) {
  unsigned char *pkt1 = NULL, *pkt2 = NULL, buf[2096] = "thcping6", buf2[6];
  unsigned char *src6 = NULL, *dst6 = NULL;
  unsigned char  dmac[7] = {0x33, 0x33, 0xff, 0x01, 0x00, 0xfe, 0x00};
  char           string[255] = "icmp6 and dst ", *interface;
  int            pkt1_len = 0, pkt2_len = 0, flags = 0, j;
  pcap_t *       p;

  if (argc < 2 || argc > 3 || strncmp(argv[1], "-h", 2) == 0) help(argv[0]);

  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  if (getenv("THC_IPV6_PPPOE") != NULL || getenv("THC_IPV6_6IN4") != NULL)
    printf("WARNING: %s is not working with injection!\n", argv[0]);

  memset(buf, 0, sizeof(buf));
  for (j = 0; j < (128 / 8); j++)
    memcpy(buf + j * 8, "thcsniff", 8);
  memset(buf2 + 2, 0, 4);
  buf2[0] = NXT_INVALID;
  buf2[1] = 1;

  interface = argv[1];
  if (argc == 3) {
    if ((dst6 = thc_resolve6(argv[2])) == NULL) {
      fprintf(stderr, "Error: not a valid target: %s\n", argv[2]);
      exit(-1);
    }
    if (dst6[0] != 0xff) oneonly = 1;
  } else
    dst6 = thc_resolve6("ff02::1");
  if ((src6 = thc_get_own_ipv6(interface, dst6, PREFER_LINK)) == NULL) {
    fprintf(stderr, "Error: no IPv6 address found for interface %s!\n",
            interface);
    exit(-1);
  }

  if ((pkt1 = thc_create_ipv6_extended(interface, PREFER_LINK, &pkt1_len, src6,
                                       dst6, 255, 0, 0, 0, 0)) == NULL)
    return -1;
  if (thc_add_icmp6(pkt1, &pkt1_len, ICMP6_ECHOREQUEST, 0, flags,
                    (unsigned char *)&buf, 128, 0) < 0)
    return -1;
  if (thc_generate_pkt(interface, NULL, dmac, pkt1, &pkt1_len) < 0) {
    fprintf(stderr, "Error: Can not generate packet, exiting ...\n");
    exit(-1);
  }

  if ((pkt2 = thc_create_ipv6_extended(interface, PREFER_LINK, &pkt2_len, src6,
                                       dst6, 255, 0, 0, 0, 0)) == NULL)
    return -1;
  if (thc_add_hdr_dst(pkt2, &pkt2_len, (unsigned char *)&buf2, sizeof(buf2)) <
      0)
    return -1;
  if (thc_add_icmp6(pkt2, &pkt2_len, ICMP6_ECHOREQUEST, 0, flags,
                    (unsigned char *)&buf, 128, 0) < 0)
    return -1;
  if (thc_generate_pkt(interface, NULL, dmac, pkt2, &pkt2_len) < 0) {
    fprintf(stderr, "Error: Can not generate packet, exiting ...\n");
    exit(-1);
  }

  strcat(string, thc_ipv62notation(src6));
  if ((p = thc_pcap_init(interface, string)) == NULL) {
    fprintf(stderr, "Error: could not capture on interface %s with string %s\n",
            interface, string);
    exit(-1);
  }
  signal(SIGALRM, alarming);
  alarm(3);
  printf("Sending sniffer detection packets to %s\n", thc_ipv62notation(dst6));
  thc_send_pkt(interface, pkt1, &pkt1_len);
  thc_send_pkt(interface, pkt2, &pkt2_len);
  thc_send_pkt(interface, pkt1, &pkt1_len);
  thc_send_pkt(interface, pkt2, &pkt2_len);
  while (1) {
    thc_pcap_check(p, (char *)check_packets, buf);
  }

  return 0;  // not reached
}
