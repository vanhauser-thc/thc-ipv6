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
  printf("%s %s (c) 2016 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf("Syntax:\n");
  printf("  %s [-t ttl] [-s src6] [-d dst6] interface hello [dr_priority]\n", prg);
  printf("  %s [-t ttl] [-s src6] [-d dst6] interface join|prune neighbor6 multicast6 target6\n\n", prg);
  printf("The hello command takes optionally the DR priority (default: 0).\n");
  printf("The join and prune commands need the multicast group to modify, the target\naddress that joins or leavs and the neighbor PIM router\n");
  printf("Use -s to spoof the source ip6, -d to send to another address than ff02::d,\nand -t to set a different TTL (default: 1)\n");
  exit(-1);
}

int main(int argc, char *argv[]) {
  unsigned char *pkt1 = NULL, buf[100];
  unsigned char *dst6 = NULL, *src6 = NULL, *multicast6, *target6, *neighbor6;
  int pkt1_len = 0, i = 0;
  char *interface;
  int ttl = 1, mode = -1, len = 0;

  if (argc < 3 || strncmp(argv[1], "-h", 2) == 0)
    help(argv[0]);

  while ((i = getopt(argc, argv, "t:s:d:")) >= 0) {
    switch (i) {
      case 't':
        ttl = atoi(optarg);
        break;
      case 's':
        src6 = thc_resolve6(optarg);
        break;
      case 'd':
        dst6 = thc_resolve6(optarg);
        break;
      default:
        fprintf(stderr, "Error: invalid option %c\n", i);
        exit(-1);
    }
  }

  interface = argv[optind];
  if (strncasecmp(argv[optind + 1], "hello", 3) == 0)
    mode = 0;
  if (strncasecmp(argv[optind + 1], "join", 3) == 0)
    mode = 1;
  if (strncasecmp(argv[optind + 1], "prune", 3) == 0) {
    mode = 2;
  }
  if (mode == -1) {
    fprintf(stderr, "Error: no mode defined, specify hello, join or prune\n");
    exit(-1);
  }
  if (mode != 0) {
    if (argc - optind != 5) {
      fprintf(stderr, "Error: join/prune mode need a multicast and target address\n");
      exit(-1);
    }
    neighbor6 = thc_resolve6(argv[optind + 2]);
    multicast6 = thc_resolve6(argv[optind + 3]);
    target6 = thc_resolve6(argv[optind + 4]);
    if (multicast6 == NULL || target6 == NULL || neighbor6 == NULL) {
      fprintf(stderr, "Error: unable to resolve addresses\n");
      exit(-1);
    }
  }

  if (dst6 == NULL)
    dst6 = thc_resolve6("ff02::d");
    
  if (thc_get_own_ipv6(interface, NULL, PREFER_LINK) == NULL) {
    fprintf(stderr, "Error: invalid interface %s\n", interface);
    exit(-1);
  }

  if ((pkt1 = thc_create_ipv6_extended(interface, PREFER_LINK, &pkt1_len, src6, dst6, ttl, 0, 0, 0, 0)) == NULL)
    return -1;
  memset(buf, 0, sizeof(buf));

  // here we set buf and len
  switch(mode) {
    case 0:
      buf[1] = 1;
      buf[3] = 2;
      buf[5] = 255;
      buf[7] = 19;
      buf[9] = 4;
      if (argc - optind >= 3) {
        i = atoi(argv[optind + 2]); 
        buf[10] = i / 256*256*256;
        buf[11] = (i / 65536) % 256;
        buf[12] = (i % 65536) / 256;
        buf[13] = i % 256;
      }
      len = 14;
      break;
    default:
      buf[0] = 2;
      memcpy(buf + 2, neighbor6, 16);
      buf[19] = 1;
      buf[21] = 255;
      buf[22] = 2;
      buf[25] = 128;
      memcpy(buf + 26, multicast6, 16);
      if (mode == 1)
        buf[43] = 1;
      else
        buf[45] = 1;
      buf[46] = 2;
      buf[48] = 7;
      buf[49] = 128;
      memcpy(buf + 50, target6, 16);
      len = 66;
//      mode = 3;
  }

  if (thc_add_pim(pkt1, &pkt1_len, mode, buf, len) < 0)
    return -1;
  if (thc_generate_pkt(interface, NULL, NULL, pkt1, &pkt1_len) < 0) {
    fprintf(stderr, "Error: Can not generate packet, exiting ...\n");
    exit(-1);
  }

  while (thc_send_pkt(interface, pkt1, &pkt1_len) < 0)
    usleep(5);

  printf("Sent PIM %s message\n", mode == 0 ? "hello" : mode == 1 ? "join" : "prune");

  return 0;
}
