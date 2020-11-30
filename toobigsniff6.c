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

unsigned char *mac6, *src6, *interface, *ip6;
unsigned int   loop = 0, go = 1, mtu, offset = 14;

void help(char *prg) {
  printf("%s %s (c) 2020 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf("Syntax: %s [-c] interface target mtu\n\n", prg);
  printf(
      "Sniff for packte from target and send an ICMPv6 too big error message "
      "based on\n");
  printf(
      "that packet with the MTU specified. If you supply a '*' as-address, any "
      "global\n");
  printf("traffic sniffed will be used.\n");
  printf(
      "If you supply the option -c the tool will not quit upon first packet "
      "match, but\ncontinue running and send packets until aborted.\n");
  //  printf("Use -r to use raw mode.\n\n");
  exit(-1);
}

void send_toobig(u_char *foo, const struct pcap_pkthdr *header,
                 const unsigned char *data) {
  unsigned char *ipv6hdr, *target;
  int            len = header->caplen;

  if (do_hdr_size) {
    ipv6hdr = (unsigned char *)(data + do_hdr_size);
    len = header->caplen - do_hdr_size;
    if ((ipv6hdr[0] & 240) != 0x60) return;
    offset = do_hdr_size;
  } else {
    ipv6hdr = (unsigned char *)(data + offset);
    len = header->caplen - offset;
  }

  if (ip6 != NULL && memcmp(ip6, ipv6hdr + 8, 16) != 0)  // is it the target?
    return;
  if (ipv6hdr[6] == NXT_ICMP6 && ipv6hdr[40] < 128)  // no ICMP Errors
    return;

  thc_toobig6(interface, src6, mac6, NULL, mtu, ipv6hdr, len);

  target = thc_ipv62notation(ipv6hdr + 8);
  printf("Sent TooBig packet to %s\n", target);
  free(target);

  if (loop == 0)  // do we loop?
    go = 0;
}

int main(int argc, char *argv[]) {
  char    string[] = "ip6 and ! src net f000::/4 and ! dst net f000::/4";
  int     rawmode = 0, i;
  pcap_t *p;

  if (argc < 3 || strncmp(argv[1], "-h", 2) == 0) help(argv[0]);

  while ((i = getopt(argc, argv, "cr")) >= 0) {
    switch (i) {
      case 'r':
        thc_ipv6_rawmode(1);
        rawmode = 1;
        offset = 0;
        break;
      case 'c':
        loop = 1;
        break;
      default:
        fprintf(stderr, "Error: invalid option %c\n", i);
        exit(-1);
    }
  }

  if (argc - optind < 3) help(argv[0]);

  if (do_hdr_size) offset = do_hdr_size;

  interface = argv[optind];
  mac6 = thc_get_own_mac(interface);
  src6 = thc_get_own_ipv6(interface, NULL, PREFER_GLOBAL);
  mtu = atoi(argv[optind + 2]);

  if (src6 == NULL || mac6 == NULL) {
    fprintf(stderr, "Error: invalid interface or IPv6 not available: %s\n",
            interface);
    exit(-1);
  }

  if (argv[optind + 1][0] == '*' || argv[optind + 1][1] == '*') {
    ip6 = NULL;
  } else {
    ip6 = thc_resolve6(argv[optind + 1]);
    if (ip6 == NULL) {
      fprintf(stderr, "Error: target address is invalid: %s\n",
              argv[optind + 1]);
      exit(-1);
    }
  }

  if ((p = thc_pcap_init(interface, string)) == NULL) {
    fprintf(stderr, "Error: could not capture on interface %s with string %s\n",
            interface, string);
    exit(-1);
  }

  printf("Watching for %s from %s (Press Control-C to end) ...\n",
         loop == 0 ? "a packet" : "packets", argv[optind + 1]);

  do {
    thc_pcap_check(p, (char *)send_toobig, NULL);
    usleep(25);
  } while (go);

  thc_pcap_close(p);
  return 0;
}
