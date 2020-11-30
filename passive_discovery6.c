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

#define MAX_ENTRIES 65536

int           maxhop = 255, dcnt = 0, do_dst = 0, noverb = 0;
unsigned char d[MAX_ENTRIES + 1][16], hostpart[8];
char *        interface, *script = NULL, exec[256], *replace = NULL, *ll;

void help(char *prg) {
  printf("%s %s (c) 2020 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf("Syntax: %s [-Ds] [-m maxhop] [-R prefix] interface [script]\n\n",
         prg);
  printf("Options:\n");
  printf(
      " -D          do also dump destination addresses (does not work with "
      "-m)\n");
  printf(" -s          do only print the addresses, no other output\n");
  printf(
      " -m maxhop   the maximum number of hops a target which is dumped may be "
      "away.\n");
  printf(
      "             0 means local only, the maximum amount to make sense is "
      "usually 5\n");
  printf(
      " -R prefix   exchange the defined prefix with the link local prefix\n");
  printf(
      "\nPassivly sniffs the network and dump all client's IPv6 addresses "
      "detected.\n");
  printf(
      "Note that in a switched environment you get better results when "
      "additionally\nstarting parasite6, however this will impact the "
      "network.\n");
  printf(
      "If a script name is specified after the interface, it is called with "
      "the\ndetected ipv6 address as first and the interface as second "
      "option.\n");
  exit(-1);
}

void detect(u_char *foo, const struct pcap_pkthdr *header,
            unsigned char *data) {
  char *ptr = data, *ptr2;
  int   i, j, k, offset = 8, doit, len = header->caplen;

  if (do_hdr_size) {
    len -= do_hdr_size;
    ptr += do_hdr_size;
    thc_dump_data(ptr, 8, "packet");
    if ((ptr[0] & 240) != 0x60) return;
  } else {
    len -= 14;
    ptr += 14;
  }

  // drop ff00::/8 and ::/128
  for (k = 0; k <= do_dst; k++) {
    doit = 0;

    if ((unsigned char)ptr[offset] != 0xff &&
        (maxhop > 254 || (unsigned char)ptr[7] >= 255 - maxhop ||
         ((unsigned char)ptr[7] >= 128 - maxhop &&
          (unsigned char)ptr[7] <= 128) ||
         ((unsigned char)ptr[7] >= 64 - maxhop && (unsigned char)ptr[7] <= 64)))
      doit = 1;
    if (memcmp(ptr + 8, d[dcnt + 1], 16) == 0) {
      if (k == 0 && (unsigned char)ptr[7] == 255 &&
          (unsigned char)ptr[6] == NXT_ICMP6 &&
          (unsigned char)ptr[40] == ICMP6_NEIGHBORSOL && len >= 64) {
        doit = 1;  // DAD packet
        offset = 48;
      } else
        doit = 0;
    }

    // is it our own address?
    if (memcmp(ptr + offset + 8, hostpart, 8) == 0) doit = 0;

    if (doit) {
      // replace prefix with link-local if -R
      if (replace != NULL)
        if (memcmp(ptr + offset, replace, 8) == 0) memcpy(ptr + offset, ll, 8);

      // check for doubles
      j = 0;
      if (dcnt > 0)
        for (i = 0; i < dcnt && j == 0; i++)
          if (memcmp(ptr + offset, d[i], 16) == 0) j = 1;

      if (j == 0) {  // no double
        ptr2 = thc_ipv62notation((char *)(ptr + offset));
        printf("%s%s\n", noverb == 0 ? "Detected: " : "", ptr2);

        if (dcnt < MAX_ENTRIES) {  // add to double list
          memcpy(d[dcnt], ptr + offset, 16);
          dcnt++;
        } else if (dcnt == MAX_ENTRIES) {  // table full? should not happen,
                                           // smells like attack
          dcnt++;
          fprintf(stderr,
                  "Warning: Table for detected IPv6 addresses is full, doubles "
                  "can occur now!\n");
        }

        if (script != NULL && fork() == 0) {  // beware, this can DOS you
          (void)wait3(NULL, WNOHANG, NULL);
          snprintf(exec, sizeof(exec), "%s %s %s\n", script, ptr2, interface);
          if (system(exec) < 0)
            fprintf(stderr, "Error: Executing failed - %s\n", exec);
          exit(0);
        }

        free(ptr2);
      }
    }

    offset += 16;
  }
}

int main(int argc, char *argv[]) {
  int   i;
  char *glob;

  if (argc < 2 || strncmp(argv[1], "-h", 2) == 0) help(argv[0]);

  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  while ((i = getopt(argc, argv, "Dsm:R:")) >= 0) {
    switch (i) {
      case 'm':
        maxhop = atoi(optarg);
        break;
      case 'D':
        do_dst = 1;
        break;
      case 's':
        noverb = 1;
        break;
      case 'R':
        if ((ll = index(optarg, '/')) != NULL) *ll = 0;
        replace = thc_resolve6(optarg);
        break;
      default:
        fprintf(stderr, "Error: invalid option %c\n", i);
        exit(-1);
    }
  }

  if (argc - optind < 1 || argc - optind > 2) help(argv[0]);

  interface = argv[optind];
  if (argc == optind + 2) script = argv[optind + 1];

  memset(d, 0, sizeof(d));
  _thc_ipv6_showerrors = 0;

  // we dont want our own address in the discovered addresses
  glob = thc_get_own_ipv6(interface, NULL, PREFER_GLOBAL);
  ll = thc_get_own_ipv6(interface, NULL, PREFER_LINK);
  if (!ll) {
    fprintf(stderr, "No IPv6 found on interface %s\n", interface);
    exit(-1);
  }
  memcpy(hostpart, ll + 8, 8);
  if (memcmp(ll + 8, glob + 8, 8) !=
      0) {  // do we have a global address with a different host part?
    memcpy(d[0], glob, 16);
    dcnt = 1;
  }

  if (do_dst < 255 && do_dst)
    fprintf(stderr,
            "Warning: it does not make sense to use the -m and -D options "
            "together!\n");

  if (noverb == 0)
    printf(
        "Started IPv6 passive system detection (Press Control-C to end) ...\n");
  return thc_pcap_function(interface, "ip6", (char *)detect, 1, NULL);

  return 0;  // never reached
}
