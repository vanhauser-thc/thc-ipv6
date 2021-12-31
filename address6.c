#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include "thc-ipv6.h"

void help(char *prg) {
  printf("%s %s (c) 2022 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf("Syntax:\n\t%s mac-address [ipv6-prefix]\n", prg);
  printf("\t%s ipv4-address [ipv6-prefix]\n", prg);
  printf("\t%s ipv6-address\n\n", prg);
  printf(
      "Converts a mac or IPv4 address to an IPv6 address (link local if no "
      "prefix is\n");
  printf(
      "given as 2nd option) or, when given an IPv6 address, prints the mac or "
      "IPv4\n");
  printf(
      "address. Prints all possible variations. Returns -1 on errors or the "
      "number of\n");
  printf("variations found\n");
  exit(-1);
}

int main(int argc, char *argv[]) {
  unsigned char *ptr, *dst6, ipv4[16] = "", ipv6[64], *prefix;
  int            i, j, k, found = 0;
  struct in_addr in;

  if (argc < 2 || argc > 3 || strncmp(argv[1], "-h", 2) == 0) help(argv[0]);

  if ((dst6 = index(argv[1], '/')) != NULL) *dst6 = 0;
  if ((dst6 = thc_resolve6(argv[1])) != NULL) {  // ipv6 address
    if (dst6[11] == 0xff && dst6[12] == 0xfe) {  // EUI-64 encoding of mac
      printf("%02x:%02x:%02x:%02x:%02x:%02x\n", (dst6[8] ^ 2), dst6[9],
             dst6[10], dst6[13], dst6[14], dst6[15]);
      return 1;
    }
    // ::ffff:ip4enc:ipv4enc support
    if (dst6[8] + dst6[9] == 0 && dst6[10] == 0xff & dst6[11] == 0xff) {
      dst6[10] = 0;
      dst6[11] = 0;
    }
    if (dst6[8] + dst6[10] + dst6[12] + dst6[14] == 0 &&
        dst6[9] != 0) {  // hexdecimal ipv4
      j = 0;
      for (i = 0; i < 4; i++)
        if (dst6[9 + i * 2] > 9) j++;
      if (j > 0) {
        sprintf(ipv4, "%d.%d.%d.%d", dst6[9], dst6[11], dst6[13], dst6[15]);
        if (inet_aton(ipv4, &in) != 0) {
          printf("%s\n", ipv4);
          found++;
        }
      }
    }
    if (dst6[8] + dst6[9] + dst6[10] + dst6[11] == 0 &&
        dst6[12] != 0) {  // hexdecimal ipv4 #2
      sprintf(ipv4, "%d.%d.%d.%d", dst6[12], dst6[13], dst6[14], dst6[15]);
      if (inet_aton(ipv4, &in) != 0) {
        printf("%s\n", ipv4);
        found++;
      }
    }
    // now try for decimal ipv4 encoding
    memset(dst6, 0, 8);
    ptr = thc_ipv62notation(dst6);
    ptr += 2;
    j = 0;
    for (i = 0; i < strlen(ptr); i++)
      if (ptr[i] > ':')
        j++;
      else if (ptr[i] == ':')
        ptr[i] = '.';
    if (j == 0 && inet_aton(ptr, &in) != 0) {
      j = 0;
      for (i = 0; i < strlen(ptr); i++)
        if (ptr[i] == '.') j++;
      if (j == 3) {
        printf("%s\n", ptr);
        found++;
      }
    }

    if (found > 0) return found;

    fprintf(stderr,
            "Error: the IPv6 address does not contain a mac or encoded IPv4 "
            "address\n");
    return -1;
  }

  // now check for a prefix argument
  if (argc == 3) {
    if ((ptr = index(argv[2], '/')) != NULL) *ptr = 0;
    if ((prefix = thc_resolve6(argv[2])) == NULL) {
      fprintf(stderr, "Error: invalid prefix: %s\n", argv[2]);
      return -1;
    }
  } else
    prefix = thc_resolve6("fe80::");

  if (index(argv[1], '.') != NULL) {  // ipv4 to ipv6
    ptr = argv[1];
    for (i = 0; i < 4; i++) {
      if ((dst6 = index(ptr, '.')) != NULL) *dst6 = 0;
      ipv4[i] = atoi(ptr);
      if ((i < 3 && dst6 == NULL) || (i == 3 && dst6 != NULL)) {
        i = 3;
        ipv4[0] = 0;
      } else if (dst6 != NULL)
        ptr = dst6 + 1;
    }
    j = 0;
    k = 0;
    for (i = 0; i < 4; i++) {
      if (ipv4[i] > 255) j++;
      if (ipv4[i] > 9) k = 1;
    }
    if (j == 0 && ipv4[0] != 0) {  // from here we know its a valid ipv4 address
      memcpy(ipv6, prefix, 8);
      memset(ipv6 + 8, 0, 8);
      for (i = 0; i < 4; i++)
        ipv6[9 + i * 2] = ipv4[i];
      printf("%s\n", thc_ipv62notation(ipv6));  // hex representation #1
      memset(ipv6 + 8, 0, 4);
      memcpy(ipv6 + 12, ipv4, 4);
      printf("%s\n", thc_ipv62notation(ipv6));  // hex representation #2
      memset(ipv6 + 8, 0, 7);
      ipv6[15] = ipv4[3];
      printf("%s\n", thc_ipv62notation(ipv6));  // hex representation #3

      if (k) {  // do we need decimal representation too, or would it be a
                // double?
        sprintf(ipv6, "::%d:%d:%d:%d", ipv4[0], ipv4[1], ipv4[2], ipv4[3]);
        dst6 = thc_resolve6(ipv6);
        memcpy(dst6, prefix, 8);
        printf("%s\n", thc_ipv62notation(dst6));
      }

      if (ipv4[3] < 10)
        return (3 + k);
      else {  // 2nd decimal representation
        sprintf(ipv6, "::%d", ipv4[3]);
        dst6 = thc_resolve6(ipv6);
        memcpy(dst6, prefix, 8);
        printf("%s\n", thc_ipv62notation(dst6));
        return (4 + k);
      }
    }
  }

  if (index(argv[1], ':') != NULL) {  // mac to ipv6
    sscanf(argv[1], "%x:%x:%x:%x:%x:%x", (unsigned int *)&k,
           (unsigned int *)&ipv6[9], (unsigned int *)&ipv6[10],
           (unsigned int *)&ipv6[13], (unsigned int *)&ipv6[14],
           (unsigned int *)&ipv6[15]);
    memcpy(ipv6, prefix, 8);
    ipv6[8] = (k ^ 2);
    ipv6[11] = 0xff;
    ipv6[12] = 0xfe;
    printf("%s\n", thc_ipv62notation(ipv6));
    return 1;
  }

  fprintf(stderr, "Error: neither a valid mac, IPv4 or IPv6 address\n");
  return -1;
}
