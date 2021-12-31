/*
 * Tests the implementation of ACLs for bypassing attacks
 *
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

extern int do_6in4;
extern int do_pppoe;
extern int do_hdr_vlan;
extern int do_hdr_off;

int sports[] = {20, 21, 22, 25, 53, 80, 111, 123, 179, 443, 8080, -1};
int sports2[] = {20, 53, 67, 68, 69, 111, 123, 161, 162, 2049, -1};

int matched = 0, port = -1, udp = 0, sport = 21000, cport, count = 0, poffset,
    poffset2, ptype, only = 0, pingtest = 0, do_hop = 0;
unsigned char *dst, *psrc, is_srcport = 0;
pcap_t *       p;

void help(char *prg) {
  printf("%s %s (c) 2022 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf("Syntax: %s [-Hu] interface destination port [test-case-no]\n\n", prg);
  printf("Performs various ACL bypass attempts to check implementations.\n");
  printf(
      "Defaults to TCP ports, option -u switches to UDP.\nOption -H prints the "
      "hop count.\n");
  printf(
      "For all test cases to work, ICMPv6 ping to the destination must be "
      "allowed.\n");
  exit(-1);
}

void ignoreit(u_char *foo, const struct pcap_pkthdr *header,
              const unsigned char *data) {
  return;
}

void check_packet(u_char *foo, const struct pcap_pkthdr *header,
                  const unsigned char *data) {
  unsigned char *    ptr = (unsigned char *)(data + 14);
  int                len = header->caplen - 14, nxt = 6, offset = 0;
  unsigned short int rsport, rdport;

  matched = -1;

  if (do_hdr_size) {
    ptr = (unsigned char *)(data + do_hdr_size);
    len -= (do_hdr_size - 14);
    if ((ptr[0] & 240) != 0x60) return;
  }

  if (ptr[nxt] == NXT_FRAG) {
    offset += 8;
    nxt = 40;
  }

  if (udp == 0 && ptr[nxt] == NXT_TCP && memcmp(dst, ptr + 8, 16) == 0 &&
      len >= 60 + offset) {
    rsport = ptr[40 + offset] * 256 + ptr[41 + offset];
    rdport = ptr[42 + offset] * 256 + ptr[43 + offset];
    // printf("rsport: %d, rdport: %d, sport %d, port %d, count %d\n", rsport,
    // rdport, sport, port, count);
    if ((is_srcport == 1 || rdport == sport + count) && rsport == port) {
      if (do_hop) printf("[%d] ", ptr[7]);
      printf("TCP");
      if ((ptr[53 + offset] & 1) > 0) printf("-FIN");
      if ((ptr[53 + offset] & 2) > 0) printf("-SYN");
      if ((ptr[53 + offset] & 4) > 0) printf("-RST");
      if ((ptr[53 + offset] & 16) > 0) printf("-ACK");
      printf(" received\n");
      matched = 1;
    }  // else printf("DEBUG: different tcp pkt seen from target (is_srcport %d,
       // rdport %d == sport %d + count %d, rsport %d == port %d)\n",
       // is_srcport, rdport, sport, count, rsport, port);
  }
  if (udp == 1 && ptr[nxt] == NXT_UDP && memcmp(dst, ptr + 8, 16) == 0 &&
      len >= 48 + offset) {
    rsport = ptr[40 + offset] * 256 + ptr[41 + offset];
    rdport = ptr[42 + offset] * 256 + ptr[43 + offset];
    if ((is_srcport == 1 || rdport == sport + count) && rsport == port) {
      if (do_hop) printf("[%d] ", ptr[7]);
      printf("UDP received\n");
    }
  }
  if (ptr[nxt] == NXT_ICMP6 &&
      (ptr[40 + offset] == ICMP6_UNREACH ||
       ptr[40 + offset] == ICMP6_PARAMPROB) &&
      len >= 96 + poffset + offset) {
    if (memcmp(dst, ptr + 72 + offset, 16) != 0) return;
    if (ptype >= 0) {
      if (ptype == NXT_FRAG && poffset == 0) {
        if (ptr[54 + offset] != NXT_FRAG && ptr[54 + offset] != NXT_DST) return;
      } else {
        if (ptr[54 + offset] != ptype) return;
        if (udp == 0 && ptr[54 + poffset2 + offset] != NXT_TCP) return;
        if (udp == 1 && ptr[54 + poffset2 + offset] != NXT_UDP) return;
      }
    } else {
      if (udp == 0 && ptr[54 + offset] != NXT_TCP) return;
      if (udp == 1 && ptr[54 + offset] != NXT_UDP) return;
    }
    rsport = ptr[88 + poffset + offset] * 256 + ptr[89 + poffset + offset];
    rdport = ptr[90 + poffset + offset] * 256 + ptr[91 + poffset + offset];
    if ((ptype == NXT_FRAG && poffset == 0) ||
        ((rsport == sport + count || is_srcport == 1) && rdport == port)) {
      matched = 1;
      if (do_hop) printf("[%d] ", ptr[7]);
      printf("ICMPv6 ");
      if (ptr[40 + offset] == ICMP6_PARAMPROB) {
        printf("Parameter Problem received\n");
        return;
      }
      switch (ptr[41 + offset]) {
        case 0:
          printf("Route");
          break;
        case 1:
          printf("Firewall");
          break;
        case 2:
          printf("Out-Of-Scope");
          break;
        case 3:
          printf("Address");
          break;
        case 4:
          printf("Port");
          break;
        case 5:
          printf("Ingress/Egress");
          break;
        case 6:
          printf("Reject");
          break;
        default:
          printf("unknown");
      }
      printf(" unreachable received\n");
    }
  } else if (ptr[nxt] == NXT_ICMP6 && ptr[40 + offset] == ICMP6_ECHOREPLY &&
             pingtest) {
    matched = 1;
    if (do_hop) printf("[%d] ", ptr[7]);
    printf("ICMPv6 Echo Reply\n");
  }
}

void check_for_reply() {
  int    ret = -1;
  time_t t;

  t = time(NULL);
  matched = 0;
  while (ret < 0) {
    usleep(10);
    thc_pcap_check(p, (char *)check_packet, NULL);
    if (matched == -1) {
      ret = -1;
      matched = 0;
    } else if (matched == 1)
      ret = 0;
    if (time(NULL) > t + 3 && ret < 0) ret = 0;
  }

  if (matched == 0)
    printf("FAILED - no reply\n");
  else if (only == 0)
    sleep(1);
}

int main(int argc, char *argv[]) {
  int            i, curr = 0;
  unsigned char  buf[3000], ch;
  unsigned char *src, string[64] = "ip6 and not src ";
  unsigned char *srcmac = NULL, *dstmac = NULL;
  thc_ipv6_hdr * hdr, *hdr3;
  int            offset = 14;
  unsigned char *pkt = NULL, *pkt2 = NULL, *pkt3 = NULL;
  int            pkt_len = 0, pkt_len2 = 0, pkt_len3 = 0;
  char *         interface;

  if (argc < 3 || strncmp(argv[1], "-h", 2) == 0) help(argv[0]);

  while ((i = getopt(argc, argv, "uH")) >= 0) {
    switch (i) {
      case 'u':
        udp = 1;
        break;
      case 'H':
        do_hop = 1;
        break;
      default:
        fprintf(stderr, "Error: invalid option -%c\n", i);
        exit(-1);
    }
  }

  if (argc - optind < 3) help(argv[0]);

  if (do_hdr_size) offset = do_hdr_size;

  interface = argv[optind];
  dst = thc_resolve6(argv[optind + 1]);
  port = atoi(argv[optind + 2]);

  if (argc - optind > 3 && argv[optind + 3] != NULL)
    only = atoi(argv[optind + 3]);

  if ((src = thc_get_own_ipv6(interface, dst, PREFER_GLOBAL)) == NULL) {
    fprintf(stderr, "Error: invalid interface %s\n", interface);
    exit(-1);
  }
  srcmac = thc_get_own_mac(interface);
  if ((dstmac = thc_get_mac(interface, src, dst)) == NULL) {
    fprintf(stderr, "ERROR: Can not resolve mac address for %s\n", argv[2]);
    exit(-1);
  }

  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  strcat(string, thc_ipv62notation(src));
  memset(buf, 0, sizeof(buf));

  if ((p = thc_pcap_init(interface, string)) == NULL) {
    fprintf(stderr, "Error: could not capture on interface %s with string %s\n",
            interface, string);
    exit(-1);
  }

  printf("Starting firewall6: mode %s against %s port %d\n",
         udp == 0 ? "TCP" : "UDP", argv[optind + 1], port);
  printf("Run a sniffer behind the firewall to see what passes through\n\n");

  curr = 0;

  /* -----------------  BEGIN OF TEST CASES ---------------- */

  if (only == ++count || only == 0) {
    printf("Test %2d: plain sending\t\t\t", count);
    poffset = 0;
    ptype = -1;
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                        dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (udp == 0) {
      if (thc_add_tcp(pkt, &pkt_len, sport + count, port, sport + count, 0,
                      TCP_SYN, 0x3840, 0, NULL, 0, NULL, 0) == -1)
        return -1;
    } else {
      if (thc_add_udp(pkt, &pkt_len, sport + count, port, 0, NULL, 0) == -1)
        return -1;
    }
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) == -1)
      return -1;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    while (thc_send_pkt(interface, pkt, &pkt_len) == -1)
      usleep(1);
    while (thc_send_pkt(interface, pkt, &pkt_len) == -1)
      usleep(1);
    check_for_reply();
    pkt = thc_destroy_packet(pkt);
    curr++;
  }

  if (only == ++count || only == 0) {
    printf("Test %2d: plain sending with data\t", count);
    poffset = 0;
    ptype = -1;
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                        dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (udp == 0) {
      if (thc_add_tcp(pkt, &pkt_len, sport + count, port, sport + count, 0,
                      TCP_SYN, 0x3840, 0, NULL, 0, buf, 1000) == -1)
        return -1;
    } else {
      if (thc_add_udp(pkt, &pkt_len, sport + count, port, 0, buf, 1000) == -1)
        return -1;
    }
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) == -1)
      return -1;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    while (thc_send_pkt(interface, pkt, &pkt_len) == -1)
      usleep(1);
    while (thc_send_pkt(interface, pkt, &pkt_len) == -1)
      usleep(1);
    check_for_reply();
    pkt = thc_destroy_packet(pkt);
    curr++;
  }

  if (only == ++count || only == 0) {
    printf("Test %2d: IPv4 ethernet type\t\t", count);
    poffset = 0;
    ptype = -1;
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                        dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (udp == 0) {
      if (thc_add_tcp(pkt, &pkt_len, sport + count, port, sport + count, 0,
                      TCP_SYN, 0x3840, 0, NULL, 0, NULL, 0) == -1)
        return -1;
    } else {
      if (thc_add_udp(pkt, &pkt_len, sport + count, port, 0, NULL, 0) == -1)
        return -1;
    }
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) == -1)
      return -1;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    hdr = (thc_ipv6_hdr *)pkt;
    if (do_hdr_size) {
      if (do_pppoe) {
        hdr->pkt[20 + do_hdr_off] = 0;  // PPP protocol value for IPv4
        hdr->pkt[21 + do_hdr_off] = 0x21;
      } else if (do_hdr_vlan && do_6in4 == 0) {
        hdr->pkt[16] = 8;  // ethernet protocol value for IPv4
        hdr->pkt[17] = 0;
      }
    } else {
      hdr->pkt[12] = 8;  // ethernet protocol value for IPv4
      hdr->pkt[13] = 0;
    }

    if (do_6in4 == 0) {
      while (thc_send_pkt(interface, pkt, &pkt_len) == -1)
        usleep(1);
      while (thc_send_pkt(interface, pkt, &pkt_len) == -1)
        usleep(1);
      check_for_reply();
    } else
      printf("skipped (6in4)\n");
    pkt = thc_destroy_packet(pkt);
    curr++;
  }

  if (only == ++count || only == 0) {
    printf("Test %2d: sending IPv5 packet\t\t", count);
    poffset = 0;
    ptype = -1;
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                        dst, 64, 0, count, 0, 5)) == NULL)
      return -1;
    if (udp == 0) {
      if (thc_add_tcp(pkt, &pkt_len, sport + count, port, sport + count, 0,
                      TCP_SYN, 0x3840, 0, NULL, 0, NULL, 0) == -1)
        return -1;
    } else {
      if (thc_add_udp(pkt, &pkt_len, sport + count, port, 0, NULL, 0) == -1)
        return -1;
    }
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) == -1)
      return -1;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    while (thc_send_pkt(interface, pkt, &pkt_len) == -1)
      usleep(1);
    while (thc_send_pkt(interface, pkt, &pkt_len) == -1)
      usleep(1);
    check_for_reply();
    pkt = thc_destroy_packet(pkt);
    curr++;
  }

  if (only == ++count || only == 0) {
    printf("Test %2d: hop-by-hop hdr (ignore option)\t", count);
    poffset = 8;
    ptype = NXT_HBH;
    poffset2 = 34;
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                        dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    memset(buf, 0, 6);
    if (thc_add_hdr_hopbyhop(pkt, &pkt_len, buf, 6) == -1) return -1;
    if (udp == 0) {
      if (thc_add_tcp(pkt, &pkt_len, sport + count, port, sport + count, 0,
                      TCP_SYN, 0x3840, 0, NULL, 0, NULL, 0) == -1)
        return -1;
    } else {
      if (thc_add_udp(pkt, &pkt_len, sport + count, port, 0, NULL, 0) == -1)
        return -1;
    }
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) == -1)
      return -1;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    while (thc_send_pkt(interface, pkt, &pkt_len) == -1)
      usleep(1);
    while (thc_send_pkt(interface, pkt, &pkt_len) == -1)
      usleep(1);
    check_for_reply();
    pkt = thc_destroy_packet(pkt);
    curr++;
  }

  if (only == ++count || only == 0) {
    printf("Test %2d: dst hdr (ignore option)\t", count);
    poffset = 8;
    ptype = NXT_DST;
    poffset2 = 34;
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                        dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    memset(buf, 0, 6);
    if (thc_add_hdr_dst(pkt, &pkt_len, buf, 6) == -1) return -1;
    if (udp == 0) {
      if (thc_add_tcp(pkt, &pkt_len, sport + count, port, sport + count, 0,
                      TCP_SYN, 0x3840, 0, NULL, 0, NULL, 0) == -1)
        return -1;
    } else {
      if (thc_add_udp(pkt, &pkt_len, sport + count, port, 0, NULL, 0) == -1)
        return -1;
    }
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) == -1)
      return -1;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    while (thc_send_pkt(interface, pkt, &pkt_len) == -1)
      usleep(1);
    while (thc_send_pkt(interface, pkt, &pkt_len) == -1)
      usleep(1);
    check_for_reply();
    pkt = thc_destroy_packet(pkt);
    curr++;
  }

  if (only == ++count || only == 0) {
    printf("Test %2d: hop-by-hop hdr router alert\t", count);
    poffset = 8;
    ptype = NXT_HBH;
    poffset2 = 34;
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                        dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    memset(buf, 0, 6);
    buf[0] = 5;
    buf[1] = 2;
    if (thc_add_hdr_hopbyhop(pkt, &pkt_len, buf, 6) == -1) return -1;
    if (udp == 0) {
      if (thc_add_tcp(pkt, &pkt_len, sport + count, port, sport + count, 0,
                      TCP_SYN, 0x3840, 0, NULL, 0, NULL, 0) == -1)
        return -1;
    } else {
      if (thc_add_udp(pkt, &pkt_len, sport + count, port, 0, NULL, 0) == -1)
        return -1;
    }
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) == -1)
      return -1;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    while (thc_send_pkt(interface, pkt, &pkt_len) == -1)
      usleep(1);
    while (thc_send_pkt(interface, pkt, &pkt_len) == -1)
      usleep(1);
    check_for_reply();
    pkt = thc_destroy_packet(pkt);
    curr++;
  }

  if (only == ++count || only == 0) {
    printf("Test %2d: 3x dst hdr (ignore option)\t", count);
    poffset = 3 * 8;
    ptype = NXT_DST;
    poffset2 = 34 + 2 * 8;
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                        dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    memset(buf, 0, 6);
    for (i = 0; i < 3; i++)
      if (thc_add_hdr_dst(pkt, &pkt_len, buf, 6) == -1) return -1;
    if (udp == 0) {
      if (thc_add_tcp(pkt, &pkt_len, sport + count, port, sport + count, 0,
                      TCP_SYN, 0x3840, 0, NULL, 0, NULL, 0) == -1)
        return -1;
    } else {
      if (thc_add_udp(pkt, &pkt_len, sport + count, port, 0, NULL, 0) == -1)
        return -1;
    }
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) == -1)
      return -1;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    while (thc_send_pkt(interface, pkt, &pkt_len) == -1)
      usleep(1);
    while (thc_send_pkt(interface, pkt, &pkt_len) == -1)
      usleep(1);
    check_for_reply();
    pkt = thc_destroy_packet(pkt);
    curr++;
  }

  if (only == ++count || only == 0) {
    printf("Test %2d: 130x dst hdr (ignore option)\t", count);
    poffset = 130 * 8;
    ptype = NXT_DST;
    poffset2 = 34 + 129 * 8;
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                        dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    memset(buf, 0, 6);
    for (i = 0; i < 130; i++)
      if (thc_add_hdr_dst(pkt, &pkt_len, buf, 6) == -1) return -1;
    if (udp == 0) {
      if (thc_add_tcp(pkt, &pkt_len, sport + count, port, sport + count, 0,
                      TCP_SYN, 0x3840, 0, NULL, 0, NULL, 0) == -1)
        return -1;
    } else {
      if (thc_add_udp(pkt, &pkt_len, sport + count, port, 0, NULL, 0) == -1)
        return -1;
    }
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) == -1)
      return -1;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    while (thc_send_pkt(interface, pkt, &pkt_len) == -1)
      usleep(1);
    while (thc_send_pkt(interface, pkt, &pkt_len) == -1)
      usleep(1);
    check_for_reply();
    pkt = thc_destroy_packet(pkt);
    curr++;
  }

  if (only == ++count || only == 0) {
    printf("Test %2d: atomic fragment\t\t", count);
    poffset = 8;
    ptype = NXT_FRAG;
    poffset2 = 34;
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                        dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (thc_add_hdr_fragment(pkt, &pkt_len, 0, 0, sport + count) == -1)
      return -1;
    if (udp == 0) {
      if (thc_add_tcp(pkt, &pkt_len, sport + count, port, sport + count, 0,
                      TCP_SYN, 0x3840, 0, NULL, 0, NULL, 0) == -1)
        return -1;
    } else {
      if (thc_add_udp(pkt, &pkt_len, sport + count, port, 0, NULL, 0) == -1)
        return -1;
    }
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) == -1)
      return -1;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    while (thc_send_pkt(interface, pkt, &pkt_len) == -1)
      usleep(1);
    while (thc_send_pkt(interface, pkt, &pkt_len) == -1)
      usleep(1);
    check_for_reply();
    pkt = thc_destroy_packet(pkt);
    curr++;
  }

  if (only == ++count || only == 0) {
    printf("Test %2d: 2x atomic fragment (same id)\t", count);
    poffset = 2 * 8;
    ptype = NXT_FRAG;
    poffset2 = 34 + 1 * 8;
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                        dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    for (i = 0; i < 2; i++)
      if (thc_add_hdr_fragment(pkt, &pkt_len, 0, 0, sport + count) == -1)
        return -1;
    if (udp == 0) {
      if (thc_add_tcp(pkt, &pkt_len, sport + count, port, sport + count, 0,
                      TCP_SYN, 0x3840, 0, NULL, 0, NULL, 0) == -1)
        return -1;
    } else {
      if (thc_add_udp(pkt, &pkt_len, sport + count, port, 0, NULL, 0) == -1)
        return -1;
    }
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) == -1)
      return -1;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    while (thc_send_pkt(interface, pkt, &pkt_len) == -1)
      usleep(1);
    while (thc_send_pkt(interface, pkt, &pkt_len) == -1)
      usleep(1);
    check_for_reply();
    pkt = thc_destroy_packet(pkt);
    curr++;
  }

  if (only == ++count || only == 0) {
    printf("Test %2d: 2x atomic fragment (diff id)\t", count);
    poffset = 2 * 8;
    ptype = NXT_FRAG;
    poffset2 = 34 + 1 * 8;
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                        dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    for (i = 0; i < 2; i++)
      if (thc_add_hdr_fragment(pkt, &pkt_len, 0, 0, sport + count * 512 + i) ==
          -1)
        return -1;
    if (udp == 0) {
      if (thc_add_tcp(pkt, &pkt_len, sport + count, port, sport + count, 0,
                      TCP_SYN, 0x3840, 0, NULL, 0, NULL, 0) == -1)
        return -1;
    } else {
      if (thc_add_udp(pkt, &pkt_len, sport + count, port, 0, NULL, 0) == -1)
        return -1;
    }
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) == -1)
      return -1;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    while (thc_send_pkt(interface, pkt, &pkt_len) == -1)
      usleep(1);
    while (thc_send_pkt(interface, pkt, &pkt_len) == -1)
      usleep(1);
    check_for_reply();
    pkt = thc_destroy_packet(pkt);
    curr++;
  }

  if (only == ++count || only == 0) {
    printf("Test %2d: 3x atomic fragment (same id)\t", count);
    poffset = 3 * 8;
    ptype = NXT_FRAG;
    poffset2 = 34 + 2 * 8;
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                        dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    for (i = 0; i < 3; i++)
      if (thc_add_hdr_fragment(pkt, &pkt_len, 0, 0, sport + count) == -1)
        return -1;
    if (udp == 0) {
      if (thc_add_tcp(pkt, &pkt_len, sport + count, port, sport + count, 0,
                      TCP_SYN, 0x3840, 0, NULL, 0, NULL, 0) == -1)
        return -1;
    } else {
      if (thc_add_udp(pkt, &pkt_len, sport + count, port, 0, NULL, 0) == -1)
        return -1;
    }
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) == -1)
      return -1;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    while (thc_send_pkt(interface, pkt, &pkt_len) == -1)
      usleep(1);
    while (thc_send_pkt(interface, pkt, &pkt_len) == -1)
      usleep(1);
    check_for_reply();
    pkt = thc_destroy_packet(pkt);
    curr++;
  }

  if (only == ++count || only == 0) {
    printf("Test %2d: 3x atomic fragment (diff id)\t", count);
    poffset = 3 * 8;
    ptype = NXT_FRAG;
    poffset2 = 34 + 2 * 8;
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                        dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    for (i = 0; i < 3; i++)
      if (thc_add_hdr_fragment(pkt, &pkt_len, 0, 0, sport + count * 512 + i) ==
          -1)
        return -1;
    if (udp == 0) {
      if (thc_add_tcp(pkt, &pkt_len, sport + count, port, sport + count, 0,
                      TCP_SYN, 0x3840, 0, NULL, 0, NULL, 0) == -1)
        return -1;
    } else {
      if (thc_add_udp(pkt, &pkt_len, sport + count, port, 0, NULL, 0) == -1)
        return -1;
    }
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) == -1)
      return -1;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    while (thc_send_pkt(interface, pkt, &pkt_len) == -1)
      usleep(1);
    while (thc_send_pkt(interface, pkt, &pkt_len) == -1)
      usleep(1);
    check_for_reply();
    pkt = thc_destroy_packet(pkt);
    curr++;
  }

  if (only == ++count || only == 0) {
    printf("Test %2d: 130x atomic fragment (same id)\t", count);
    poffset = 0;
    ptype = NXT_FRAG;
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                        dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    for (i = 0; i < 130; i++)
      if (thc_add_hdr_fragment(pkt, &pkt_len, 0, 0, sport + count) == -1)
        return -1;
    if (udp == 0) {
      if (thc_add_tcp(pkt, &pkt_len, sport + count, port, sport + count, 0,
                      TCP_SYN, 0x3840, 0, NULL, 0, NULL, 0) == -1)
        return -1;
    } else {
      if (thc_add_udp(pkt, &pkt_len, sport + count, port, 0, NULL, 0) == -1)
        return -1;
    }
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) == -1)
      return -1;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    while (thc_send_pkt(interface, pkt, &pkt_len) == -1)
      usleep(1);
    while (thc_send_pkt(interface, pkt, &pkt_len) == -1)
      usleep(1);
    check_for_reply();
    pkt = thc_destroy_packet(pkt);
    curr++;
  }

  if (only == ++count || only == 0) {
    printf("Test %2d: 130x atomic fragment (diff id)\t", count);
    poffset = 0;
    ptype = NXT_FRAG;
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                        dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    for (i = 0; i < 130; i++)
      if (thc_add_hdr_fragment(pkt, &pkt_len, 0, 0, sport + count * 512 + i) ==
          -1)
        return -1;
    if (udp == 0) {
      if (thc_add_tcp(pkt, &pkt_len, sport + count, port, sport + count, 0,
                      TCP_SYN, 0x3840, 0, NULL, 0, NULL, 0) == -1)
        return -1;
    } else {
      if (thc_add_udp(pkt, &pkt_len, sport + count, port, 0, NULL, 0) == -1)
        return -1;
    }
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) == -1)
      return -1;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    while (thc_send_pkt(interface, pkt, &pkt_len) == -1)
      usleep(1);
    while (thc_send_pkt(interface, pkt, &pkt_len) == -1)
      usleep(1);
    check_for_reply();
    pkt = thc_destroy_packet(pkt);
    curr++;
  }

  if (only == ++count || only == 0) {
    printf("Test %2d: 260x atomic fragment (same id)\t", count);
    poffset = 0;
    ptype = NXT_FRAG;
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                        dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    for (i = 0; i < 260; i++)
      if (thc_add_hdr_fragment(pkt, &pkt_len, 0, 0, sport + count) == -1)
        return -1;
    if (udp == 0) {
      if (thc_add_tcp(pkt, &pkt_len, sport + count, port, sport + count, 0,
                      TCP_SYN, 0x3840, 0, NULL, 0, NULL, 0) == -1)
        return -1;
    } else {
      if (thc_add_udp(pkt, &pkt_len, sport + count, port, 0, NULL, 0) == -1)
        return -1;
    }
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) == -1)
      return -1;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    hdr = (thc_ipv6_hdr *)pkt;
    thc_send_as_fragment6(interface, src, dst, NXT_FRAG, hdr->pkt + 40 + offset,
                          hdr->pkt_len - 40 - offset, 1240);
    thc_send_as_fragment6(interface, src, dst, NXT_FRAG, hdr->pkt + 40 + offset,
                          hdr->pkt_len - 40 - offset, 1240);
    check_for_reply();
    pkt = thc_destroy_packet(pkt);
    curr++;
  }

  if (only == ++count || only == 0) {
    printf("Test %2d: 260x atomic fragment (diff id)\t", count);
    poffset = 0;
    ptype = NXT_FRAG;
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                        dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    for (i = 0; i < 260; i++)
      if (thc_add_hdr_fragment(pkt, &pkt_len, 0, 0, sport + count * 512 + i) ==
          -1)
        return -1;
    if (udp == 0) {
      if (thc_add_tcp(pkt, &pkt_len, sport + count, port, sport + count, 0,
                      TCP_SYN, 0x3840, 0, NULL, 0, NULL, 0) == -1)
        return -1;
    } else {
      if (thc_add_udp(pkt, &pkt_len, sport + count, port, 0, NULL, 0) == -1)
        return -1;
    }
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) == -1)
      return -1;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    hdr = (thc_ipv6_hdr *)pkt;
    thc_send_as_fragment6(interface, src, dst, NXT_FRAG, hdr->pkt + 40 + offset,
                          hdr->pkt_len - 40 - offset, 1240);
    thc_send_as_fragment6(interface, src, dst, NXT_FRAG, hdr->pkt + 40 + offset,
                          hdr->pkt_len - 40 - offset, 1240);
    check_for_reply();
    pkt = thc_destroy_packet(pkt);
    curr++;
  }

  if (only == ++count || only == 0) {
    printf("Test %2d: 2kb dst hdr\t\t\t", count);
    poffset = 0;
    ptype = NXT_FRAG;
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                        dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    memset(buf, 0, sizeof(buf));
    if (thc_add_hdr_dst(pkt, &pkt_len, buf, 2040 - 2) == -1) return -1;
    if (udp == 0) {
      if (thc_add_tcp(pkt, &pkt_len, sport + count, port, sport + count, 0,
                      TCP_SYN, 0x3840, 0, NULL, 0, NULL, 0) == -1)
        return -1;
    } else {
      if (thc_add_udp(pkt, &pkt_len, sport + count, port, 0, NULL, 0) == -1)
        return -1;
    }
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) == -1)
      return -1;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    hdr = (thc_ipv6_hdr *)pkt;
    thc_send_as_fragment6(interface, src, dst, NXT_DST, hdr->pkt + 40 + offset,
                          hdr->pkt_len - 40 - offset, 1240);
    thc_send_as_fragment6(interface, src, dst, NXT_DST, hdr->pkt + 40 + offset,
                          hdr->pkt_len - 40 - offset, 1240);
    check_for_reply();
    pkt = thc_destroy_packet(pkt);
    curr++;
  }

  if (only == ++count || only == 0) {
    printf("Test %2d: 2kb dst + dst hdr\t\t", count);
    poffset = 0;
    ptype = NXT_FRAG;
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                        dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    memset(buf, 0, sizeof(buf));
    if (thc_add_hdr_dst(pkt, &pkt_len, buf, 2040 - 2) == -1) return -1;
    if (thc_add_hdr_dst(pkt, &pkt_len, buf, 6) == -1) return -1;
    if (udp == 0) {
      if (thc_add_tcp(pkt, &pkt_len, sport + count, port, sport + count, 0,
                      TCP_SYN, 0x3840, 0, NULL, 0, NULL, 0) == -1)
        return -1;
    } else {
      if (thc_add_udp(pkt, &pkt_len, sport + count, port, 0, NULL, 0) == -1)
        return -1;
    }
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) == -1)
      return -1;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    hdr = (thc_ipv6_hdr *)pkt;
    thc_send_as_fragment6(interface, src, dst, NXT_DST, hdr->pkt + 40 + offset,
                          hdr->pkt_len - 40 - offset, 1240);
    thc_send_as_fragment6(interface, src, dst, NXT_DST, hdr->pkt + 40 + offset,
                          hdr->pkt_len - 40 - offset, 1240);
    check_for_reply();
    pkt = thc_destroy_packet(pkt);
    curr++;
  }

  if (only == ++count || only == 0) {
    printf("Test %2d: 32x 2kb dst hdr\t\t", count);
    poffset = 0;
    ptype = NXT_FRAG;
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                        dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    memset(buf, 0, sizeof(buf));
    for (i = 0; i < 32; i++)
      if (thc_add_hdr_dst(pkt, &pkt_len, buf, 2040 - 2) == -1) return -1;
    if (udp == 0) {
      if (thc_add_tcp(pkt, &pkt_len, sport + count, port, sport + count, 0,
                      TCP_SYN, 0x3840, 0, NULL, 0, NULL, 0) == -1)
        return -1;
    } else {
      if (thc_add_udp(pkt, &pkt_len, sport + count, port, 0, NULL, 0) == -1)
        return -1;
    }
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) == -1)
      return -1;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    hdr = (thc_ipv6_hdr *)pkt;
    thc_send_as_fragment6(interface, src, dst, NXT_DST, hdr->pkt + 40 + offset,
                          hdr->pkt_len - 40 - offset, 1240);
    thc_send_as_fragment6(interface, src, dst, NXT_DST, hdr->pkt + 40 + offset,
                          hdr->pkt_len - 40 - offset, 1240);
    check_for_reply();
    pkt = thc_destroy_packet(pkt);
    curr++;
  }

  if (only == ++count || only == 0) {
    printf("Test %2d: 2x dst hdr + 2x frag\t\t", count);
    poffset = 0;
    ptype = NXT_FRAG;
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                        dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    memset(buf, 0, sizeof(buf));
    if (thc_add_hdr_dst(pkt, &pkt_len, buf, 2040 - 2) == -1) return -1;
    if (thc_add_hdr_dst(pkt, &pkt_len, buf, 6) == -1) return -1;
    if (thc_add_hdr_fragment(pkt, &pkt_len, 0, 0, sport + count) == -1)
      return -1;
    if (udp == 0) {
      if (thc_add_tcp(pkt, &pkt_len, sport + count, port, sport + count, 0,
                      TCP_SYN, 0x3840, 0, NULL, 0, NULL, 0) == -1)
        return -1;
    } else {
      if (thc_add_udp(pkt, &pkt_len, sport + count, port, 0, NULL, 0) == -1)
        return -1;
    }
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) == -1)
      return -1;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    hdr = (thc_ipv6_hdr *)pkt;
    thc_send_as_fragment6(interface, src, dst, NXT_DST, hdr->pkt + 40 + offset,
                          hdr->pkt_len - 40 - offset, 1240);
    thc_send_as_fragment6(interface, src, dst, NXT_DST, hdr->pkt + 40 + offset,
                          hdr->pkt_len - 40 - offset, 1240);
    check_for_reply();
    pkt = thc_destroy_packet(pkt);
    curr++;
  }

  if (only == ++count || only == 0) {
    printf("Test %2d: 4x dst hdr + 3x frag\t\t", count);
    poffset = 0;
    ptype = NXT_FRAG;
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                        dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    memset(buf, 0, sizeof(buf));
    if (thc_add_hdr_dst(pkt, &pkt_len, buf, 2040 - 2) == -1) return -1;
    if (thc_add_hdr_dst(pkt, &pkt_len, buf, 6) == -1) return -1;
    if (thc_add_hdr_fragment(pkt, &pkt_len, 0, 0, sport + count) == -1)
      return -1;
    if (thc_add_hdr_dst(pkt, &pkt_len, buf, 2040 - 2) == -1) return -1;
    if (thc_add_hdr_dst(pkt, &pkt_len, buf, 6) == -1) return -1;
    if (thc_add_hdr_fragment(pkt, &pkt_len, 0, 0, sport + count) == -1)
      return -1;
    if (udp == 0) {
      if (thc_add_tcp(pkt, &pkt_len, sport + count, port, sport + count, 0,
                      TCP_SYN, 0x3840, 0, NULL, 0, NULL, 0) == -1)
        return -1;
    } else {
      if (thc_add_udp(pkt, &pkt_len, sport + count, port, 0, NULL, 0) == -1)
        return -1;
    }
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) == -1)
      return -1;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    hdr = (thc_ipv6_hdr *)pkt;
    thc_send_as_fragment6(interface, src, dst, NXT_DST, hdr->pkt + 40 + offset,
                          hdr->pkt_len - 40 - offset, 1240);
    thc_send_as_fragment6(interface, src, dst, NXT_DST, hdr->pkt + 40 + offset,
                          hdr->pkt_len - 40 - offset, 1240);
    check_for_reply();
    pkt = thc_destroy_packet(pkt);
    curr++;
  }

  if (only == ++count || only == 0) {
    printf("Test %2d: frag type first+middle\t\t", count);
    poffset = 0;
    ptype = NXT_FRAG;

    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                        dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (udp == 0) {
      if (thc_add_tcp(pkt, &pkt_len, sport + count, port, sport + count, 0,
                      TCP_SYN, 0x3840, 0, NULL, 0, buf, 2500) == -1)
        return -1;
    } else {
      if (thc_add_udp(pkt, &pkt_len, sport + count, port, 0, buf, 2500) == -1)
        return -1;
    }
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) == -1)
      return -1;
    hdr = (thc_ipv6_hdr *)pkt;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;

    if ((pkt2 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len2,
                                         src, dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (thc_add_hdr_fragment(pkt2, &pkt_len2, 0, 1, sport + count) == -1)
      return -1;
    if (thc_add_data6(pkt2, &pkt_len2, NXT_TCP, hdr->pkt + 40 + offset, 1232) ==
        -1)
      return -1;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt2, &pkt_len2) ==
        -1)
      return -1;
    pkt2 = thc_destroy_packet(pkt2);

    if ((pkt2 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len2,
                                         src, dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (thc_add_hdr_fragment(pkt2, &pkt_len2, 1232 / 8, 1, sport + count) == -1)
      return -1;
    if (thc_add_data6(pkt2, &pkt_len2, NXT_TCP, hdr->pkt + 1232 + 40 + offset,
                      1232) == -1)
      return -1;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt2, &pkt_len2) ==
        -1)
      return -1;
    pkt2 = thc_destroy_packet(pkt2);

    if ((pkt2 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len2,
                                         src, dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (thc_add_hdr_fragment(pkt2, &pkt_len2, 2464 / 8, 0, sport + count) == -1)
      return -1;
    if (thc_add_data6(pkt2, &pkt_len2, NXT_ICMP6, hdr->pkt + 2464 + 40 + offset,
                      hdr->pkt_len - 2464 - 40 - do_hdr_size) == -1)
      return -1;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt2, &pkt_len2) ==
        -1)
      return -1;
    pkt2 = thc_destroy_packet(pkt2);

    pkt = thc_destroy_packet(pkt);
    check_for_reply();

    curr++;
  }

  if (only == ++count || only == 0) {
    printf("Test %2d: frag type first (2nd)\t\t", count);
    poffset = 0;
    ptype = NXT_FRAG;

    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                        dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (udp == 0) {
      if (thc_add_tcp(pkt, &pkt_len, sport + count, port, sport + count, 0,
                      TCP_SYN, 0x3840, 0, NULL, 0, buf, 2500) == -1)
        return -1;
    } else {
      if (thc_add_udp(pkt, &pkt_len, sport + count, port, 0, buf, 2500) == -1)
        return -1;
    }
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) == -1)
      return -1;
    hdr = (thc_ipv6_hdr *)pkt;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;

    if ((pkt2 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len2,
                                         src, dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (thc_add_hdr_fragment(pkt2, &pkt_len2, 1232 / 8, 1, sport + count) == -1)
      return -1;
    if (thc_add_data6(pkt2, &pkt_len2, NXT_ICMP6, hdr->pkt + 1232 + 40 + offset,
                      1232) == -1)
      return -1;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt2, &pkt_len2) ==
        -1)
      return -1;
    pkt2 = thc_destroy_packet(pkt2);

    if ((pkt2 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len2,
                                         src, dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (thc_add_hdr_fragment(pkt2, &pkt_len2, 0, 1, sport + count) == -1)
      return -1;
    if (thc_add_data6(pkt2, &pkt_len2, NXT_TCP, hdr->pkt + 40 + offset, 1232) ==
        -1)
      return -1;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt2, &pkt_len2) ==
        -1)
      return -1;
    pkt2 = thc_destroy_packet(pkt2);

    if ((pkt2 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len2,
                                         src, dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (thc_add_hdr_fragment(pkt2, &pkt_len2, 2464 / 8, 0, sport + count) == -1)
      return -1;
    if (thc_add_data6(pkt2, &pkt_len2, NXT_ICMP6, hdr->pkt + 2464 + 40 + offset,
                      hdr->pkt_len - 2464 - 40 - do_hdr_size) == -1)
      return -1;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt2, &pkt_len2) ==
        -1)
      return -1;
    pkt2 = thc_destroy_packet(pkt2);

    pkt = thc_destroy_packet(pkt);
    check_for_reply();

    curr++;
  }

  if (only == ++count || only == 0) {
    printf("Test %2d: frag type first #2 (overlap)\t", count);
    poffset = 0;
    ptype = NXT_FRAG;

    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                        dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (udp == 0) {
      if (thc_add_tcp(pkt, &pkt_len, sport + count, port, sport + count, 0,
                      TCP_SYN, 0x3840, 0, NULL, 0, buf, 2500) == -1)
        return -1;
    } else {
      if (thc_add_udp(pkt, &pkt_len, sport + count, port, 0, buf, 2500) == -1)
        return -1;
    }
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) == -1)
      return -1;
    hdr = (thc_ipv6_hdr *)pkt;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;

    // interface, ip6, dst, type, frhdr->pkt + 40 + myoff, frhdr->pkt_len - 40 -
    // myoff, 1232, 0
    thc_send_as_overlapping_first_fragment6(interface, src, dst, NXT_ICMP6,
                                            hdr->pkt + 40, hdr->pkt_len - 40,
                                            1232, 0);

    pkt = thc_destroy_packet(pkt);
    check_for_reply();

    curr++;
  }

  if (only == ++count || only == 0) {
    printf("Test %2d: frag type first #3 (resend#2)\t", count);

    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                        dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (thc_add_hdr_fragment(pkt, &pkt_len, 0, 1, sport + count) < 0) return -1;
    if (thc_add_icmp6(pkt, &pkt_len, ICMP6_ECHOREQUEST, 0, count,
                      (unsigned char *)&buf, 12, 0) < 0)
      return -1;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len) ==
        -1)
      return -1;
    pkt = thc_destroy_packet(pkt);

    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                        dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (thc_add_hdr_fragment(pkt, &pkt_len, 0, 0, sport + count) < 0) return -1;
    if (udp == 0) {
      if (thc_add_tcp(pkt, &pkt_len, sport + count, port, sport + count, 0,
                      TCP_SYN, 0x3840, 0, NULL, 0, NULL, 0) == -1)
        return -1;
    } else {
      if (thc_add_udp(pkt, &pkt_len, sport + count, port, 0, NULL, 0) == -1)
        return -1;
    }
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len) ==
        -1)
      return -1;
    pkt = thc_destroy_packet(pkt);

    check_for_reply();

    curr++;
  }

  if (only == ++count || only == 0) {
    printf("Test %2d: frag type first #4 (resend#2L)\t", count);
    poffset = 0;
    ptype = NXT_FRAG;

    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                        dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (thc_add_hdr_fragment(pkt, &pkt_len, 0, 1, sport + count) < 0) return -1;
    if (thc_add_icmp6(pkt, &pkt_len, ICMP6_ECHOREQUEST, 0, count,
                      (unsigned char *)&buf, 0, 0) < 0)
      return -1;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len) ==
        -1)
      return -1;
    pkt = thc_destroy_packet(pkt);

    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                        dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (thc_add_hdr_fragment(pkt, &pkt_len, 0, 0, sport + count) < 0) return -1;
    if (udp == 0) {
      if (thc_add_tcp(pkt, &pkt_len, sport + count, port, sport + count, 0,
                      TCP_SYN, 0x3840, 0, NULL, 0, NULL, 0) == -1)
        return -1;
    } else {
      if (thc_add_udp(pkt, &pkt_len, sport + count, port, 0, NULL, 0) == -1)
        return -1;
    }
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len) ==
        -1)
      return -1;
    pkt = thc_destroy_packet(pkt);

    check_for_reply();

    curr++;
  }

  if (only == ++count || only == 0) {
    printf("Test %2d: frag type middle+last\t\t", count);
    poffset = 0;
    ptype = NXT_FRAG;

    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                        dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (udp == 0) {
      if (thc_add_tcp(pkt, &pkt_len, sport + count, port, sport + count, 0,
                      TCP_SYN, 0x3840, 0, NULL, 0, buf, 2500) == -1)
        return -1;
    } else {
      if (thc_add_udp(pkt, &pkt_len, sport + count, port, 0, buf, 2500) == -1)
        return -1;
    }
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) == -1)
      return -1;
    hdr = (thc_ipv6_hdr *)pkt;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;

    if ((pkt2 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len2,
                                         src, dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (thc_add_hdr_fragment(pkt2, &pkt_len2, 0, 1, sport + count) == -1)
      return -1;
    if (thc_add_data6(pkt2, &pkt_len2, NXT_ICMP6, hdr->pkt + 40 + offset,
                      1232) == -1)
      return -1;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt2, &pkt_len2) ==
        -1)
      return -1;
    pkt2 = thc_destroy_packet(pkt2);

    if ((pkt2 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len2,
                                         src, dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (thc_add_hdr_fragment(pkt2, &pkt_len2, 1232 / 8, 1, sport + count) == -1)
      return -1;
    if (thc_add_data6(pkt2, &pkt_len2, NXT_TCP, hdr->pkt + 1232 + 40 + offset,
                      1232) == -1)
      return -1;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt2, &pkt_len2) ==
        -1)
      return -1;
    pkt2 = thc_destroy_packet(pkt2);

    if ((pkt2 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len2,
                                         src, dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (thc_add_hdr_fragment(pkt2, &pkt_len2, 2464 / 8, 0, sport + count) == -1)
      return -1;
    if (thc_add_data6(pkt2, &pkt_len2, NXT_TCP, hdr->pkt + 2464 + 40 + offset,
                      hdr->pkt_len - 2464 - 40 - do_hdr_size) == -1)
      return -1;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt2, &pkt_len2) ==
        -1)
      return -1;
    pkt2 = thc_destroy_packet(pkt2);

    pkt = thc_destroy_packet(pkt);
    check_for_reply();

    curr++;
  }

  if (only == ++count || only == 0) {
    printf("Test %2d: frag type middle(first)+last\t", count);
    poffset = 0;
    ptype = NXT_FRAG;

    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                        dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (udp == 0) {
      if (thc_add_tcp(pkt, &pkt_len, sport + count, port, sport + count, 0,
                      TCP_SYN, 0x3840, 0, NULL, 0, buf, 2500) == -1)
        return -1;
    } else {
      if (thc_add_udp(pkt, &pkt_len, sport + count, port, 0, buf, 2500) == -1)
        return -1;
    }
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) == -1)
      return -1;
    hdr = (thc_ipv6_hdr *)pkt;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;

    if ((pkt2 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len2,
                                         src, dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (thc_add_hdr_fragment(pkt2, &pkt_len2, 1232 / 8, 1, sport + count) == -1)
      return -1;
    if (thc_add_data6(pkt2, &pkt_len2, NXT_TCP, hdr->pkt + 1232 + 40 + offset,
                      1232) == -1)
      return -1;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt2, &pkt_len2) ==
        -1)
      return -1;
    pkt2 = thc_destroy_packet(pkt2);

    if ((pkt2 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len2,
                                         src, dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (thc_add_hdr_fragment(pkt2, &pkt_len2, 0, 1, sport + count) == -1)
      return -1;
    if (thc_add_data6(pkt2, &pkt_len2, NXT_ICMP6, hdr->pkt + 40 + offset,
                      1232) == -1)
      return -1;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt2, &pkt_len2) ==
        -1)
      return -1;
    pkt2 = thc_destroy_packet(pkt2);

    if ((pkt2 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len2,
                                         src, dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (thc_add_hdr_fragment(pkt2, &pkt_len2, 2464 / 8, 0, sport + count) == -1)
      return -1;
    if (thc_add_data6(pkt2, &pkt_len2, NXT_TCP, hdr->pkt + 2464 + 40 + offset,
                      hdr->pkt_len - 2464 - 40 - do_hdr_size) == -1)
      return -1;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt2, &pkt_len2) ==
        -1)
      return -1;
    pkt2 = thc_destroy_packet(pkt2);

    pkt = thc_destroy_packet(pkt);
    check_for_reply();

    curr++;
  }

  if (only == ++count || only == 0) {
    printf("Test %2d: frag type last\t\t\t", count);
    poffset = 0;
    ptype = NXT_FRAG;

    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                        dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (udp == 0) {
      if (thc_add_tcp(pkt, &pkt_len, sport + count, port, sport + count, 0,
                      TCP_SYN, 0x3840, 0, NULL, 0, buf, 2500) == -1)
        return -1;
    } else {
      if (thc_add_udp(pkt, &pkt_len, sport + count, port, 0, buf, 2500) == -1)
        return -1;
    }
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) == -1)
      return -1;
    hdr = (thc_ipv6_hdr *)pkt;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;

    if ((pkt2 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len2,
                                         src, dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (thc_add_hdr_fragment(pkt2, &pkt_len2, 0, 1, sport + count) == -1)
      return -1;
    if (thc_add_data6(pkt2, &pkt_len2, NXT_ICMP6, hdr->pkt + 40 + offset,
                      1232) == -1)
      return -1;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt2, &pkt_len2) ==
        -1)
      return -1;
    pkt2 = thc_destroy_packet(pkt2);

    if ((pkt2 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len2,
                                         src, dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (thc_add_hdr_fragment(pkt2, &pkt_len2, 1232 / 8, 1, sport + count) == -1)
      return -1;
    if (thc_add_data6(pkt2, &pkt_len2, NXT_ICMP6, hdr->pkt + 1232 + 40 + offset,
                      1232) == -1)
      return -1;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt2, &pkt_len2) ==
        -1)
      return -1;
    pkt2 = thc_destroy_packet(pkt2);

    if ((pkt2 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len2,
                                         src, dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (thc_add_hdr_fragment(pkt2, &pkt_len2, 2464 / 8, 0, sport + count) == -1)
      return -1;
    if (thc_add_data6(pkt2, &pkt_len2, NXT_TCP, hdr->pkt + 2464 + 40 + offset,
                      hdr->pkt_len - 2464 - 40 - do_hdr_size) == -1)
      return -1;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt2, &pkt_len2) ==
        -1)
      return -1;
    pkt2 = thc_destroy_packet(pkt2);

    pkt = thc_destroy_packet(pkt);
    check_for_reply();

    curr++;
  }

  if (only == ++count || only == 0) {
    printf("Test %2d: frag type last #2\t\t", count);
    poffset = 0;
    ptype = NXT_FRAG;

    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                        dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (udp == 0) {
      if (thc_add_tcp(pkt, &pkt_len, sport + count, port, sport + count, 0,
                      TCP_SYN, 0x3840, 0, NULL, 0, buf, 2500) == -1)
        return -1;
    } else {
      if (thc_add_udp(pkt, &pkt_len, sport + count, port, 0, buf, 2500) == -1)
        return -1;
    }
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) == -1)
      return -1;
    hdr = (thc_ipv6_hdr *)pkt;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;

    // interface, ip6, dst, type, frhdr->pkt + 40 + myoff, frhdr->pkt_len - 40 -
    // myoff, 1232, 0
    thc_send_as_overlapping_last_fragment6(interface, src, dst, NXT_ICMP6,
                                           hdr->pkt + 40, hdr->pkt_len - 40,
                                           1232, 0);

    pkt = thc_destroy_packet(pkt);
    check_for_reply();

    curr++;
  }

  if (only == ++count || only == 0) {
    printf("Test %2d: overlapping ping first\t\t", count);
    poffset = 0;
    ptype = NXT_FRAG;
    memset(buf, 0, 1024);

    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                        dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (thc_add_hdr_dst(pkt, &pkt_len, buf, 14) == -1) return -1;
    if (thc_add_hdr_dst(pkt, &pkt_len, buf, 6) == -1) return -1;
    if (udp == 0) {
      if (thc_add_tcp(pkt, &pkt_len, sport + count, port, sport + count, 0,
                      TCP_SYN, 0x3840, 0, NULL, 0, buf, 0) == -1)
        return -1;
    } else {
      if (thc_add_udp(pkt, &pkt_len, sport + count, port, 0, buf, 0) == -1)
        return -1;
    }
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) == -1)
      return -1;
    hdr = (thc_ipv6_hdr *)pkt;

    if ((pkt3 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len3,
                                         src, dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (thc_add_hdr_dst(pkt3, &pkt_len3, buf, 14) == -1) return -1;
    if (thc_add_hdr_dst(pkt3, &pkt_len3, buf, 6) == -1) return -1;
    if (thc_add_icmp6(pkt3, &pkt_len3, ICMP6_ECHOREQUEST, 0, sport + count, buf,
                      8, 0) == -1)
      return -1;
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3) == -1)
      return -1;
    hdr3 = (thc_ipv6_hdr *)pkt3;

    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;

    if ((pkt2 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len2,
                                         src, dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (thc_add_hdr_fragment(pkt2, &pkt_len2, 0, 1, sport + count) == -1)
      return -1;
    if (thc_add_data6(pkt2, &pkt_len2, NXT_DST, hdr3->pkt + 40 + offset, 16) ==
        -1)
      return -1;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt2, &pkt_len2) ==
        -1)
      return -1;
    pkt2 = thc_destroy_packet(pkt2);

    if ((pkt2 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len2,
                                         src, dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (thc_add_hdr_fragment(pkt2, &pkt_len2, 2, 0, sport + count) == -1)
      return -1;
    if (thc_add_data6(pkt2, &pkt_len2, NXT_DST, hdr->pkt + 40 + offset + 16,
                      hdr->pkt_len - 40 - offset - 16) == -1)
      return -1;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt2, &pkt_len2) ==
        -1)
      return -1;
    pkt2 = thc_destroy_packet(pkt2);

    if ((pkt2 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len2,
                                         src, dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (thc_add_hdr_fragment(pkt2, &pkt_len2, 8 / 8, 1, sport + count) == -1)
      return -1;
    if (thc_add_data6(pkt2, &pkt_len2, NXT_DST, hdr3->pkt + 40 + offset + 8,
                      24) == -1)
      return -1;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt2, &pkt_len2) ==
        -1)
      return -1;
    pkt2 = thc_destroy_packet(pkt2);

    pkt = thc_destroy_packet(pkt);
    pkt3 = thc_destroy_packet(pkt3);
    pingtest = 1;
    check_for_reply();
    pingtest = 0;

    curr++;
  }

  if (only == ++count || only == 0) {
    printf("Test %2d: overlapping ping last\t\t", count);
    poffset = 0;
    ptype = NXT_FRAG;
    memset(buf, 0, 1024);

    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                        dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (thc_add_hdr_dst(pkt, &pkt_len, buf, 14) == -1) return -1;
    if (thc_add_hdr_dst(pkt, &pkt_len, buf, 6) == -1) return -1;
    if (udp == 0) {
      if (thc_add_tcp(pkt, &pkt_len, sport + count, port, sport + count, 0,
                      TCP_SYN, 0x3840, 0, NULL, 0, buf, 0) == -1)
        return -1;
    } else {
      if (thc_add_udp(pkt, &pkt_len, sport + count, port, 0, buf, 0) == -1)
        return -1;
    }
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) == -1)
      return -1;
    hdr = (thc_ipv6_hdr *)pkt;

    if ((pkt3 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len3,
                                         src, dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (thc_add_hdr_dst(pkt3, &pkt_len3, buf, 14) == -1) return -1;
    if (thc_add_hdr_dst(pkt3, &pkt_len3, buf, 6) == -1) return -1;
    if (thc_add_icmp6(pkt3, &pkt_len3, ICMP6_ECHOREQUEST, 0, sport + count, buf,
                      8, 0) == -1)
      return -1;
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3) == -1)
      return -1;
    hdr3 = (thc_ipv6_hdr *)pkt3;

    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;

    if ((pkt2 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len2,
                                         src, dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (thc_add_hdr_fragment(pkt2, &pkt_len2, 0, 1, sport + count) == -1)
      return -1;
    if (thc_add_data6(pkt2, &pkt_len2, NXT_DST, hdr3->pkt + 40 + offset, 16) ==
        -1)
      return -1;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt2, &pkt_len2) ==
        -1)
      return -1;
    pkt2 = thc_destroy_packet(pkt2);

    if ((pkt2 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len2,
                                         src, dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (thc_add_hdr_fragment(pkt2, &pkt_len2, 8 / 8, 1, sport + count) == -1)
      return -1;
    if (thc_add_data6(pkt2, &pkt_len2, NXT_DST, hdr3->pkt + 40 + offset + 8,
                      24) == -1)
      return -1;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt2, &pkt_len2) ==
        -1)
      return -1;
    pkt2 = thc_destroy_packet(pkt2);

    if ((pkt2 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len2,
                                         src, dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (thc_add_hdr_fragment(pkt2, &pkt_len2, 2, 0, sport + count) == -1)
      return -1;
    if (thc_add_data6(pkt2, &pkt_len2, NXT_DST, hdr->pkt + 40 + offset + 16,
                      hdr->pkt_len - 40 - offset - 16) == -1)
      return -1;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt2, &pkt_len2) ==
        -1)
      return -1;
    pkt2 = thc_destroy_packet(pkt2);

    pkt = thc_destroy_packet(pkt);
    pkt3 = thc_destroy_packet(pkt3);
    pingtest = 1;
    check_for_reply();
    pingtest = 0;

    curr++;
  }

  if (only == ++count || only == 0) {
    printf("Test %2d: resend 2nd fake pkt\t\t", count);
    poffset = 0;
    ptype = NXT_FRAG;
    memset(buf, 0, 1024);

    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                        dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (thc_add_hdr_hopbyhop(pkt, &pkt_len, buf, 14) == -1) return -1;
    if (thc_add_hdr_dst(pkt, &pkt_len, buf, 6) == -1) return -1;
    if (udp == 0) {
      if (thc_add_tcp(pkt, &pkt_len, sport + count, port, sport + count, 0,
                      TCP_SYN, 0x3840, 0, NULL, 0, buf, 40) == -1)
        return -1;
    } else {
      if (thc_add_udp(pkt, &pkt_len, sport + count, port, 0, buf, 40) == -1)
        return -1;
    }
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) == -1)
      return -1;
    hdr = (thc_ipv6_hdr *)pkt;

    if ((pkt3 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len3,
                                         src, dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (thc_add_hdr_hopbyhop(pkt3, &pkt_len3, buf, 14) == -1) return -1;
    if (thc_add_hdr_dst(pkt3, &pkt_len3, buf, 6) == -1) return -1;
    if (thc_add_icmp6(pkt3, &pkt_len3, ICMP6_ECHOREQUEST, 0, sport + count, buf,
                      32, 0) == -1)
      return -1;
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt3, &pkt_len3) == -1)
      return -1;
    hdr3 = (thc_ipv6_hdr *)pkt3;

    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;

    if ((pkt2 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len2,
                                         src, dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (thc_add_hdr_hopbyhop(pkt2, &pkt_len2, buf, 512 - 2) == -1) return -1;
    if (thc_add_hdr_fragment(pkt2, &pkt_len2, 0, 1, sport + count) == -1)
      return -1;
    if (thc_add_data6(pkt2, &pkt_len2, NXT_DST, hdr3->pkt + 40 + offset, 16) ==
        -1)
      return -1;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt2, &pkt_len2) ==
        -1)
      return -1;
    pkt2 = thc_destroy_packet(pkt2);

    if ((pkt2 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len2,
                                         src, dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (thc_add_hdr_hopbyhop(pkt2, &pkt_len2, buf, 512 - 2) == -1) return -1;
    if (thc_add_hdr_fragment(pkt2, &pkt_len2, 2, 1, sport + count) == -1)
      return -1;
    if (thc_add_data6(pkt2, &pkt_len2, NXT_DST, hdr3->pkt + 40 + offset + 16,
                      32) == -1)
      return -1;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt2, &pkt_len2) ==
        -1)
      return -1;
    pkt2 = thc_destroy_packet(pkt2);

    if ((pkt2 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len2,
                                         src, dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (thc_add_hdr_hopbyhop(pkt2, &pkt_len2, buf, 512 - 2) == -1) return -1;
    if (thc_add_hdr_fragment(pkt2, &pkt_len2, 2, 1, sport + count) == -1)
      return -1;
    if (thc_add_data6(pkt2, &pkt_len2, NXT_DST, hdr->pkt + 40 + offset + 16,
                      32) == -1)
      return -1;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt2, &pkt_len2) ==
        -1)
      return -1;
    pkt2 = thc_destroy_packet(pkt2);

    if ((pkt2 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len2,
                                         src, dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (thc_add_hdr_hopbyhop(pkt2, &pkt_len2, buf, 512 - 2) == -1) return -1;
    if (thc_add_hdr_fragment(pkt2, &pkt_len2, 6, 0, sport + count) == -1)
      return -1;
    if (thc_add_data6(pkt2, &pkt_len2, NXT_DST, hdr->pkt + 40 + offset + 48,
                      hdr->pkt_len - 40 - offset - 48) == -1)
      return -1;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt2, &pkt_len2) ==
        -1)
      return -1;
    pkt2 = thc_destroy_packet(pkt2);

    pkt = thc_destroy_packet(pkt);
    pkt3 = thc_destroy_packet(pkt3);
    pingtest = 1;
    check_for_reply();
    pingtest = 0;

    curr++;
  }

  if (only == ++count || only == 0) {
    printf("Test %2d: Bad TLV handling\t\t", count);
    memset(buf, 0, sizeof(buf));
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                        dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (thc_add_hdr_hopbyhop(pkt, &pkt_len, buf, 6) == -1) return -1;
    buf[0] = 1;   // T
    buf[1] = 12;  // L
    if (thc_add_hdr_dst(pkt, &pkt_len, buf, 6) == -1) return -1;

    if ((pkt2 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len2,
                                         src, dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    memset(buf, 0, sizeof(buf));
    if (thc_add_hdr_hopbyhop(pkt2, &pkt_len2, buf, 6) == -1) return -1;
    buf[0] = 1;  // T
    buf[1] = 4;  // L
    if (thc_add_hdr_dst(pkt2, &pkt_len2, buf, 6) == -1) return -1;
    if (thc_add_tcp(pkt2, &pkt_len2, sport + count, port, sport + count, 0,
                    TCP_SYN, 0x3840, 0, NULL, 0, NULL, 0) == -1)
      return -1;
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt2, &pkt_len2) == -1)
      return -1;

    hdr = (thc_ipv6_hdr *)pkt2;
    if (thc_add_icmp6(pkt, &pkt_len, ICMP6_ECHOREQUEST, 0, count,
                      hdr->pkt + hdr->pkt_len - 20, 20, 0) == -1)
      return -1;
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) == -1)
      return -1;

    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    while (thc_send_pkt(interface, pkt, &pkt_len) == -1)
      usleep(1);
    while (thc_send_pkt(interface, pkt, &pkt_len) == -1)
      usleep(1);
    pingtest = 1;
    check_for_reply();
    pingtest = 0;
    pkt2 = thc_destroy_packet(pkt2);
    pkt = thc_destroy_packet(pkt);
    memset(buf, 0, sizeof(buf));

    curr++;
  }

  if (only == ++count || only == 0) {
    printf("Test %2d: Bad TLV handling #2\t\t", count);
    memset(buf, 0, sizeof(buf));
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                        dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    buf[0] = 1;   // T
    buf[1] = 12;  // L
    if (thc_add_hdr_dst(pkt, &pkt_len, buf, 6) == -1) return -1;
    buf[0] = 1;        // T
    buf[1] = 12;       // L
    buf[6] = NXT_TCP;  // fake dst hdr
    buf[7] = 1;   // 16 byte length of fake hdr, jumping over 8 byte of icmp hdr
    buf[8] = 1;   // T fake
    buf[9] = 12;  // L fake
    if (thc_add_hdr_dst(pkt, &pkt_len, buf, 14) == -1) return -1;

    if ((pkt2 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len2,
                                         src, dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (thc_add_tcp(pkt2, &pkt_len2, sport + count, port, sport + count, 0,
                    TCP_SYN, 0x3840, 0, NULL, 0, NULL, 0) == -1)
      return -1;
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt2, &pkt_len2) == -1)
      return -1;

    hdr = (thc_ipv6_hdr *)pkt2;
    if (thc_add_icmp6(pkt, &pkt_len, ICMP6_ECHOREQUEST, 0, count,
                      hdr->pkt + hdr->pkt_len - 20, 20, 0) == -1)
      return -1;
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) == -1)
      return -1;

    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    while (thc_send_pkt(interface, pkt, &pkt_len) == -1)
      usleep(1);
    while (thc_send_pkt(interface, pkt, &pkt_len) == -1)
      usleep(1);
    pingtest = 1;
    check_for_reply();
    pingtest = 0;
    pkt2 = thc_destroy_packet(pkt2);
    pkt = thc_destroy_packet(pkt);
    memset(buf, 0, sizeof(buf));

    curr++;
  }

  if (only == ++count || only == 0) {
    printf("Test %2d: Bad TLV handling #2 reverse\t", count);
    memset(buf, 0, sizeof(buf));
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                        dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    buf[0] = 1;   // T
    buf[1] = 12;  // L
    if (thc_add_hdr_dst(pkt, &pkt_len, buf, 6) == -1) return -1;
    buf[0] = 1;          // T
    buf[1] = 12;         // L
    buf[6] = NXT_ICMP6;  // fake dst hdr
    buf[7] = 3;   // 32 byte length of fake hdr, jumping over 24 byte of tcp hdr
    buf[8] = 1;   // T fake
    buf[9] = 28;  // L fake
    if (thc_add_hdr_dst(pkt, &pkt_len, buf, 14) == -1) return -1;

    if ((pkt2 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len2,
                                         src, dst, 64, 0, count, 0, 0)) == NULL)
      return -1;
    if (thc_add_icmp6(pkt2, &pkt_len2, ICMP6_ECHOREQUEST, 0, count, NULL, 0,
                      0) == -1)
      return -1;
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt2, &pkt_len2) == -1)
      return -1;

    hdr = (thc_ipv6_hdr *)pkt2;
    memset(hdr->pkt + hdr->pkt_len - 12, 0, 4);
    if (thc_add_tcp(pkt, &pkt_len, sport + count, port, sport + count, 0,
                    TCP_SYN, 0x3840, 0, NULL, 0, hdr->pkt + hdr->pkt_len - 12,
                    12) == -1)
      return -1;
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) == -1)
      return -1;

    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    while (thc_send_pkt(interface, pkt, &pkt_len) == -1)
      usleep(1);
    while (thc_send_pkt(interface, pkt, &pkt_len) == -1)
      usleep(1);
    pingtest = 1;
    check_for_reply();
    pingtest = 0;
    pkt2 = thc_destroy_packet(pkt2);
    pkt = thc_destroy_packet(pkt);
    memset(buf, 0, sizeof(buf));

    curr++;
  }

  if (only == ++count || only == 0) {
    i = 0;
    ch = 'a';
    is_srcport = 1;
    if (udp == 0) {
      while (sports[i] != -1) {
        printf("Test %2d%c: plain with srcport %d \t", count, ch++, sports[i]);
        poffset = 0;
        ptype = -1;
        if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                            src, dst, 64, 0, count, 0, 0)) ==
            NULL)
          return -1;
        if (thc_add_tcp(pkt, &pkt_len, sports[i], port, sport + count, 0,
                        TCP_SYN, 0x3840, 0, NULL, 0, buf, 0) == -1)
          return -1;
        if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) == -1)
          return -1;
        while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
          ;
        while (thc_send_pkt(interface, pkt, &pkt_len) == -1)
          usleep(1);
        while (thc_send_pkt(interface, pkt, &pkt_len) == -1)
          usleep(1);
        check_for_reply();
        pkt = thc_destroy_packet(pkt);
        i++;
      }
    } else {
      while (sports2[i] != -1) {
        printf("Test %2d%c: plain with srcport %d \t", count, ch++, sports2[i]);
        poffset = 0;
        ptype = -1;
        if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                            src, dst, 64, 0, count, 0, 0)) ==
            NULL)
          return -1;
        if (thc_add_udp(pkt, &pkt_len, sports2[i], port, 0, buf, 1000) == -1)
          return -1;
        if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) == -1)
          return -1;
        while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
          ;
        while (thc_send_pkt(interface, pkt, &pkt_len) == -1)
          usleep(1);
        while (thc_send_pkt(interface, pkt, &pkt_len) == -1)
          usleep(1);
        check_for_reply();
        pkt = thc_destroy_packet(pkt);
        i++;
      }
    }
    curr++;
    is_srcport = 0;
  }

  /* -----------------  END OF TEST CASES ---------------- */

  printf("\nDone.\n");
  thc_pcap_close(p);

  return 0;
}
