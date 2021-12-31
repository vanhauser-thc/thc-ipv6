/*
 * Test:
 *       1. next header = hopbyhop, but no header
 *       2. next header = hopbyhop, but invalid length in hopbyhop header
 *       3. next header = hophyhop + no_next, but ip6 length longer than claimed
 *       4. next header = hophyhop + no_next, but ip6 length shorter than
 * claimed
 *       5. 90 extension ignored headers
 *       6. 65535 byte packet (fragmented) with 3850 extension ignored headers
 *       7. jumbo packet (fragmented) with 7700 extension ignored headers
 *       8-10: same as 5-9 but final length larger than real packet
 *       11. 180 hop-by-bop headers
 *       12. forwarding header with 255 segements lefts (but only 1 defined)
 *
 *
 *       misc:
 *         - toobig6 with mtu = 600 on target
 *         - alive6 with target ff02::1 and router = target
 *         - alive6 with target = target and router = target (1shot frag +
 * forward)
 *         - rsmurf on target
 */

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
int cont = 0;

void help(char *prg) {
  printf("%s %s (c) 2022 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf("Syntax: %s interface\n\n", prg);
  printf(
      "Identifies test packets by the implementation6 tool, useful to check "
      "what\n");
  printf("packets passed a firewall\n");
  //  printf("Use -r to use raw mode.\n\n");
  exit(-1);
}

void check_packet(u_char *foo, const struct pcap_pkthdr *header,
                  const unsigned char *data) {
  unsigned char *ipv6hdr;
  unsigned char  buf[20];
  int            add = 0, len = header->caplen;

  if (debug) {
    printf("DEBUG: packet received\n");
    thc_dump_data((unsigned char *)data, header->caplen, "Received Packet");
  }

  if (rawmode == 0) {
    if (do_hdr_size) {
      ipv6hdr = (unsigned char *)(data + do_hdr_size);
      len -= do_hdr_size;
      if ((ipv6hdr[0] & 240) != 0x60) return;
    } else {
      ipv6hdr = (unsigned char *)(data + 14);
      len -= 14;
    }
  } else
    ipv6hdr = (unsigned char *)data;

  if (ipv6hdr[0] >> 4 != 6) return;  // not an ipv6 packet

  if (ipv6hdr[6] == NXT_ICMP6 &&
      (ipv6hdr[40] == ICMP6_NEIGHBORSOL || ipv6hdr[40] == ICMP6_NEIGHBORADV ||
       ipv6hdr[40] == ICMP6_PARAMPROB || ipv6hdr[40] == ICMP6_TTLEXEED))
    return;

  if (len >= 136) {
    if (ipv6hdr[6] == 0 && ipv6hdr[40] == 0 && ipv6hdr[48] == 0) {
      printf("   Detected (potential) implementation6 test case #%d %s\n", 3,
             cont == 3 ? "(cont'd)" : "");
      cont = 3;
      return;
    }
    buf[0] = ipv6hdr[124];
    memset(buf + 1, buf[0], sizeof(buf) - 1);
    if (memcmp(ipv6hdr + 128, buf, sizeof(buf)) == 0) {
      printf("   Detected (potential) implementation6 test case #%d %s\n",
             buf[0], cont == buf[0] ? "(cont'd)" : "");
      cont = buf[0];
      return;
    }
  }

  if (len >= 46) {
    switch (ipv6hdr[6]) {
      case NXT_ICMP6:
        if (1 == 1) {
          switch (ipv6hdr[40]) {
            case ICMP6_PINGREQUEST:
              if (ipv6hdr[44] == 0x34 && ipv6hdr[45] == 0x56 &&
                  ipv6hdr[46] == 0x78 && ipv6hdr[47] == 0x90 &&
                  ipv6hdr[52] == 'A') {
                printf(
                    "   Detected (potential) implementation6 standard thc-ipv6 "
                    "ping request%s\n",
                    cont == -1 ? " (cont'd)" : "");
                cont = -1;
              }
              return;
              break;
            case ICMP6_INFOREQUEST:
              if (ipv6hdr[48] == 20 + add) {
                printf(
                    "   Detected (potential) implementation6 test case #%d\n",
                    20 + add);
                cont = 0;
              }
              return;
              break;
            case ICMP6_INVNEIGHBORSOL:
              printf("   Detected (potential) implementation6 test case #%d\n",
                     21 + add);
              cont = 0;
              return;
              break;
            case ICMP6_CERTPATHSOL:
              if (ipv6hdr[45] == 23 + add) {
                printf(
                    "   Detected (potential) implementation6 test case #%d\n",
                    23 + add);
                cont = 0;
              }
              return;
              break;
            default:
              break;
          }
        }
        return;
        break;
      case NXT_OPTS:
        if (ipv6hdr[64] == ICMP6_MOBILE_PREFIXSOL) {
          if (ipv6hdr[69] == 22 + add) {
            printf("   Detected (potential) implementation6 test case #%d\n",
                   22 + add);
            cont = 0;
          }
          return;
        }
        break;
      default:
        break;
    }
  }

  return;
}

int main(int argc, char *argv[]) {
  unsigned char string[64] = "ip6";
  char *        interface;

  if (argv[1] != NULL && strcmp(argv[1], "-r") == 0) {
    thc_ipv6_rawmode(1);
    rawmode = 1;
    argv++;
    argc--;
  }

  if (argc != 2 || strncmp(argv[1], "-h", 2) == 0) help(argv[0]);
  interface = argv[1];

  setvbuf(stdout, NULL, _IONBF, 0);

  printf(
      "Waiting for implementation check packets on %s, press Control-C to "
      "end.\n",
      interface);
  if (thc_pcap_function(interface, string, (char *)check_packet, 0, NULL) < 0) {
    fprintf(stderr, "Error: could not capture on interface %s with string %s\n",
            interface, string);
    exit(-1);
  }
  // never returns

  return 0;
}
