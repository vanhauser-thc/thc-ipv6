/*
 * Tests various IPv6 specific options for their implementations
 * This can also be used to test firewalls, check what it passes.
 * A sniffer on the other side of the firewall or running implementation6d
 * shows you what got through.
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

int ret_code = 1, matched = 0, gtype1, gtype1a, gtype2, gtype2a, gpos, epos,
    onecase = 0;
unsigned char *gpattern, *gsrc, *gdst, etype, ecode;

void help(char *prg) {
  printf("%s %s (c) 2022 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf(
      "Syntax: %s [-p] [-s sourceip6] interface destination "
      "[test-case-number]\n\n",
      prg);
  printf("Options:\n");
  printf("  -s sourceip6  use the specified source IPv6 address\n");
  printf(
      "  -p            do not perform an alive check at the beginning and "
      "end\n");
  printf(
      "\nPerforms some IPv6 implementation checks, can be used to test "
      "some\nfirewall features too. Takes approx. 2 minutes to complete.\n");
  exit(-1);
}

void ignoreit(u_char *foo, const struct pcap_pkthdr *header,
              const unsigned char *data) {
  return;
}

void check_packet_n(u_char *foo, const struct pcap_pkthdr *header,
                    const unsigned char *data) {
  unsigned char *ipv6hdr = (unsigned char *)data, len = header->caplen;
  int            off = 0;

  ipv6hdr = (unsigned char *)(data + 14);
  len -= 14;
  if (do_hdr_size) {
    ipv6hdr = (unsigned char *)(data + do_hdr_size);
    len -= (do_hdr_size - 14);
    if ((ipv6hdr[0] & 240) != 0x60) return;
  }

  if (debug) {
    printf("DEBUG: packet received\n");
    thc_dump_data(ipv6hdr, len, "Received Packet");
  }
  if (ipv6hdr[6] == NXT_FRAG) off = 8;
  if (86 + off < len) {
    if (debug) printf("\nDEBUG: packet too short\n");
    return;
  }
  if (ipv6hdr[6] == NXT_ICMP6 &&
      (ipv6hdr[40] == ICMP6_NEIGHBORSOL || ipv6hdr[40] == ICMP6_TTLEXEED))
    return;
  if (off == 8 &&
      (ipv6hdr[40] == NXT_ICMP6 && (ipv6hdr[40 + off] == ICMP6_NEIGHBORSOL ||
                                    ipv6hdr[40 + off] == ICMP6_TTLEXEED)))
    return;
  if ((ipv6hdr[6] == NXT_ICMP6 && ipv6hdr[40] == ICMP6_NEIGHBORADV) ||
      (off == 8 && ipv6hdr[40] == NXT_ICMP6 &&
       ipv6hdr[40 + off] == ICMP6_NEIGHBORADV)) {
    if (memcmp(ipv6hdr + 8, gdst, 16) == 0 &&
        memcmp(ipv6hdr + 24, gsrc, 16) == 0) {
      matched = 2;
      return;
    }
  } else if ((ipv6hdr[6] == NXT_ICMP6 && ipv6hdr[40] == ICMP6_PARAMPROB) ||
             (off == 8 && ipv6hdr[40] == NXT_ICMP6 &&
              ipv6hdr[40 + off] == ICMP6_PARAMPROB)) {
    if (memcmp(ipv6hdr + 8, gsrc, 16) == 0 &&
        memcmp(ipv6hdr + 24, gdst, 16) == 0) {
      matched = 1;
      etype = ipv6hdr[40];
      ecode = ipv6hdr[41];
      return;
    }
  }

  return;
}

int check_for_reply_n(pcap_t *p, unsigned char *src, unsigned char *dst) {
  int    ret = -1;
  time_t t;

  t = time(NULL);
  matched = 0;
  gsrc = src, gdst = dst;
  while (ret < 0) {
    (void)thc_pcap_check(p, (char *)check_packet_n, NULL);
    if (matched > 0) ret = 0;
    if (time(NULL) > t + 2 && ret < 0) ret = 0;
  }

  if (matched <= 0) printf("FAILED - no reply\n");
  if (matched == 1) {
    printf("FAILED - error reply [%d:%d]\n", etype, ecode);
    if (onecase == 0) sleep(2);
  }
  if (matched == 2) {
    printf("PASSED - we got a reply\n");
    ret_code = 0;
  }

  usleep(500);
  return matched;
}

void check_packet(u_char *foo, const struct pcap_pkthdr *header,
                  const unsigned char *data) {
  unsigned char *ipv6hdr = (unsigned char *)(data + 14);
  int            len = header->caplen - 14, off = 0;

  if (do_hdr_size) {
    ipv6hdr = (unsigned char *)(data + do_hdr_size);
    len -= (do_hdr_size - 14);
    if ((ipv6hdr[0] & 240) != 0x60) return;
  }

  matched = 0;
  if (debug) {
    printf("DEBUG: packet received\n");
    thc_dump_data(ipv6hdr, len, "Received Packet");
  }
  if (ipv6hdr[6] == NXT_FRAG) off = 8;
  if (gpos + off > len && (epos == 0 || epos + off > len)) {
    matched = -1;
    if (debug) printf("\nDEBUG: packet too short (2)\n");
    return;
  }
  if ((ipv6hdr[6] == NXT_ICMP6 || (off == 8 && ipv6hdr[40] == NXT_ICMP6)) &&
      (ipv6hdr[40 + off] == ICMP6_NEIGHBORSOL ||
       ipv6hdr[40] == ICMP6_NEIGHBORADV ||
       ipv6hdr[40 + off] == ICMP6_TTLEXEED) &&
      ipv6hdr[40 + off] != gtype2 && ipv6hdr[40 + off] != gtype2a) {
    matched = -1;
    return;
  }
  // printf("gpos: %d, pattern %x, found %x\n", gpos, gpattern[0],
  // ipv6hdr[gpos]); printf("epos: %d, pattern %x, found %x\n", epos,
  // gpattern[0], ipv6hdr[epos]);
  if (gpos > 0 && memcmp(ipv6hdr + gpos + off, gpattern, 4) != 0) {
    matched = -1;
    if (debug) printf("\nDEBUG: packet contents different\n");
    if (epos == 0) return;
  } else {
    matched = 1;
    etype = ipv6hdr[40];
    ecode = ipv6hdr[41];
  }
  if (epos > 0 && epos < len &&
      memcmp(ipv6hdr + epos + off, gpattern, 4) == 0) {
    matched = 1;
    etype = ipv6hdr[40];
    ecode = ipv6hdr[41];
  }
  if ((ipv6hdr[6] == gtype1 || gtype1 == 0) &&
      (ipv6hdr[40] == gtype2 || gtype2 == 0) &&
      (gpos <= 0 || (gpos < len && memcmp(ipv6hdr + gpos, gpattern, 4) == 0)))
    matched = 2;
  if (off == 8 && ((ipv6hdr[40] == gtype1 || gtype1 == 0) &&
                   (ipv6hdr[40 + off] == gtype2 || gtype2 == 0) &&
                   (gpos <= 0 || (gpos < len && memcmp(ipv6hdr + gpos + off,
                                                       gpattern, 4) == 0))))
    matched = 2;
  if ((ipv6hdr[6] == gtype1a || gtype1a == 0) &&
      (ipv6hdr[40] == gtype2a || gtype2a == 0) &&
      (gpos <= 0 ||
       (gpos + off < len && memcmp(ipv6hdr + gpos, gpattern, 4) == 0)))
    matched = 2;
  if (off == 8 &&
      ((ipv6hdr[40] == gtype1a || gtype1a == 0) &&
       (ipv6hdr[40 + off] == gtype2a || gtype2a == 0) &&
       (gpos <= 0 ||
        (gpos + off < len && memcmp(ipv6hdr + gpos + off, gpattern, 4) == 0))))
    matched = 2;
  if (debug)
    printf(
        "\nDEBUG: hdr[6] %d|%d == %d, hdr[40] %d|%d == %d, pos[%d/%d] "
        "%02x%02x%02x%02x == %02x%02x%02x%02x\n",
        ipv6hdr[6], gtype1, gtype1a, ipv6hdr[40], gtype2, gtype2a, gpos, epos,
        gpos == 0 ? 0 : ipv6hdr[gpos], gpos == 0 ? 0 : ipv6hdr[gpos + 1],
        gpos == 0 ? 0 : ipv6hdr[gpos + 2], gpos == 0 ? 0 : ipv6hdr[gpos + 3],
        gpos == 0 ? 0 : gpattern[0], gpos == 0 ? 0 : gpattern[1],
        gpos == 0 ? 0 : gpattern[2], gpos == 0 ? 0 : gpattern[3]);

  return;
}

int check_for_reply(pcap_t *p, int type1, int type2, int type1a, int type2a,
                    int pos, int pos2, unsigned char *pattern) {
  int    ret = -1;
  time_t t;

  t = time(NULL);
  matched = 0;
  gtype1 = type1;
  gtype1a = type1a, gtype2 = type2;
  gtype2a = type2a, gpos = pos;
  epos = pos2;
  gpattern = pattern;
  while (ret < 0) {
    if (thc_pcap_check(p, (char *)check_packet, NULL) > 0) ret = 1;
    if (matched == -1) {
      ret = -1;
      matched = 0;
    }
    if (time(NULL) > t + 2 && ret < 0) ret = 0;
  }

  if (matched == 0) printf("FAILED - no reply\n");
  if (matched == 1) {
    printf("FAILED - error reply [%d:%d]\n", etype, ecode);
    if (onecase == 0) sleep(2);
  }
  if (matched == 2) {
    printf("PASSED - we got a reply\n");
    ret_code = 0;
  }

  usleep(500);
  return matched;
}

int check_alive(pcap_t *p, char *interface, unsigned char *src,
                unsigned char *dst) {
  int    ret = -2;
  time_t t;

  while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
    ;
  thc_ping6(interface, src, dst, 16, 1);
  t = time(NULL);
  while (ret < 0) {
    if (thc_pcap_check(p, (char *)ignoreit, NULL) > 0) ret = 1;
    if (time(NULL) > t + 1 && ret == -2) {
      thc_ping6(interface, src, dst, 16, 1);
      ret = -1;
    }
    if (time(NULL) > t + 2 && ret < 0) ret = 0;
  }

  return ret > 0 ? 1 : 0;
}

int main(int argc, char *argv[]) {
  int           test = 0, count = 1;
  unsigned char buf[1500], bla[1500], bigbla[65536], tests[256],
      string[64] = "ip6 and dst ", string2[64] = "ip6 and src ";
  unsigned char *dst6, *ldst6 = malloc(16), *src6 = NULL, *lsrc6, *mcast6;
  unsigned char *srcmac = NULL, *dstmac = NULL, *routers[2], null_buffer[6];
  thc_ipv6_hdr * hdr;
  int            i, j, k, srcmtu, fragsize, use_srcroute_type = -1, offset = 14;
  pcap_t *       p;
  unsigned char *pkt = NULL, *pkt2 = NULL, *pkt3 = NULL;
  int            pkt_len = 0, pkt_len2 = 0, pkt_len3 = 0, noping = 0;
  char *         interface;

  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  if (argc < 3 || strncmp(argv[1], "-h", 2) == 0) help(argv[0]);

  while ((i = getopt(argc, argv, "pds:")) >= 0) {
    switch (i) {
      case 'p':
        noping = 1;
        break;
      case 'd':
        debug = 1;
        break;
      case 's':
        src6 = thc_resolve6(optarg);
        break;
      default:
        fprintf(stderr, "Error: unknown option %c\n", i);
        exit(-1);
    }
  }

  interface = argv[optind];
  dst6 = thc_resolve6(argv[optind + 1]);
  if (dst6 == NULL) {
    fprintf(stderr, "Error: can not resolve %s to a valid IPv6 address\n",
            argv[optind + 1]);
    exit(-1);
  }
  memcpy(ldst6, dst6, 16);
  memset(ldst6 + 2, 0, 6);
  ldst6[0] = 0xfe;
  ldst6[1] = 0x80;
  mcast6 = thc_resolve6("ff02::1");
  if (argc >= optind + 3) {
    test = atoi(argv[optind + 2]);
    onecase = 1;
  }
  memset(buf, 0, sizeof(buf));
  memset(null_buffer, 0, sizeof(null_buffer));
  if (do_hdr_size) offset = do_hdr_size;

  if (src6 == NULL) src6 = thc_get_own_ipv6(interface, dst6, PREFER_GLOBAL);
  if (src6 != NULL && src6[0] == 0xfe)
    lsrc6 = src6;
  else
    lsrc6 = thc_get_own_ipv6(interface, ldst6, PREFER_LINK);
  if (lsrc6 == NULL) {
    fprintf(stderr, "Error: invalid interface %s\n", interface);
    exit(-1);
  }
  strcat(string, thc_ipv62notation(src6));
  strcat(string2, thc_ipv62notation(dst6));
  srcmac = thc_get_own_mac(interface);
  if ((dstmac = thc_get_mac(interface, src6, dst6)) == NULL) {
    fprintf(stderr, "ERROR: Can not resolve mac address for %s\n", argv[2]);
    exit(-1);
  }
  if ((srcmtu = thc_get_mtu(interface)) <= 0) {
    fprintf(stderr, "ERROR: can not get mtu from interface %s\n", interface);
    exit(-1);
  }
  fragsize = ((srcmtu - 62) / 8) * 8;

  if ((p = thc_pcap_init(interface, string)) == NULL) {
    fprintf(stderr, "Error: could not capture on interface %s with string %s\n",
            interface, string);
    exit(-1);
  }

  setvbuf(stdout, NULL, _IONBF, 0);
  memset(tests, 0, sizeof(tests));

  printf("Performing implementation checks on %s via %s:\n", argv[optind + 1],
         argv[optind]);
  if (noping == 0) {
    if (check_alive(p, interface, src6, dst6) == 0) {
      fprintf(stderr, "Error: target %s is not alive via direct ping6!\n",
              argv[optind + 1]);
      exit(-1);
    } else
      printf("Test  0: normal ping6\t\t\t\tPASSED - we got a reply\n");
  }

  /********************** TEST CASES ************************/

  if (test == 0 || test == count) {
    printf("Test %2d: hop-by-hop ignore option\t\t", count);
    memset(bla, count % 256, sizeof(bla));
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    memset(buf, 0, sizeof(buf));
    buf[0] = NXT_IGNORE;
    buf[1] = 0;
    if (thc_add_hdr_hopbyhop(pkt, &pkt_len, (unsigned char *)&buf, 6) < 0)
      return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, 150, 0);
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ICMP6, ICMP6_PINGREPLY, NXT_ICMP6,
                        ICMP6_PINGREPLY, 100, 0, bla))
      tests[count] = 1;
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: hop-by-hop ignore option 2kb size\t", count);
    memset(bla, count % 256, sizeof(bla));
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    memset(bigbla, 0, sizeof(bigbla));
    bigbla[0] = NXT_IGNORE;
    bigbla[1] = 0;
    if (thc_add_hdr_hopbyhop(pkt, &pkt_len, (unsigned char *)&bigbla, 2046) < 0)
      return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, 150, 0);
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    hdr = (thc_ipv6_hdr *)pkt;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_send_as_fragment6(
            interface, src6, dst6, NXT_HBH, hdr->pkt + 40 + offset,
            hdr->pkt_len - 40 - offset,
            hdr->pkt_len > fragsize
                ? fragsize
                : (((hdr->pkt_len - 40 - 14) / 16) + 1) * 8) < 0)
      return -1;
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ICMP6, ICMP6_PINGREPLY, NXT_ICMP6,
                        ICMP6_PINGREPLY, 100, 0, bla))
      tests[count] = 1;
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: 2 hop-by-hop headers\t\t\t", count);
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    memset(bla, count % 256, sizeof(bla));
    memset(buf, 0, sizeof(buf));
    buf[0] = NXT_IGNORE;
    buf[1] = 0;
    for (i = 0; i < 2; i++)
      if (thc_add_hdr_hopbyhop(pkt, &pkt_len, (unsigned char *)&buf, 6) < 0)
        return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, 150, 0);
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ICMP6, ICMP6_PINGREPLY, NXT_ICMP6,
                        ICMP6_PINGREPLY, 130, 0, bla))
      tests[count] = 1;
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: 128 hop-by-hop headers\t\t\t", count);
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    memset(bla, count % 256, sizeof(bla));
    memset(buf, 0, sizeof(buf));
    buf[0] = NXT_IGNORE;
    buf[1] = 0;
    for (i = 0; i < 128; i++)
      if (thc_add_hdr_hopbyhop(pkt, &pkt_len, (unsigned char *)&buf, 6) < 0)
        return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, 150, 0);
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ICMP6, ICMP6_PINGREPLY, NXT_ICMP6,
                        ICMP6_PINGREPLY, 130, 1200, bla))
      tests[count] = 1;
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: destination ignore option\t\t", count);
    memset(bla, count % 256, sizeof(bla));
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    memset(buf, 0, sizeof(buf));
    buf[0] = NXT_IGNORE;
    buf[1] = 0;
    if (thc_add_hdr_dst(pkt, &pkt_len, (unsigned char *)&buf, 6) < 0) return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, 150, 0);
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ICMP6, ICMP6_PINGREPLY, NXT_ICMP6,
                        ICMP6_PINGREPLY, 100, 0, bla))
      tests[count] = 1;
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: destination ignore option 2kb size\t", count);
    memset(bla, count % 256, sizeof(bla));
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    memset(bigbla, 0, sizeof(bigbla));
    bigbla[0] = NXT_IGNORE;
    bigbla[1] = 0;
    if (thc_add_hdr_dst(pkt, &pkt_len, (unsigned char *)&bigbla, 2046) < 0)
      return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, 150, 0);
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    hdr = (thc_ipv6_hdr *)pkt;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_send_as_fragment6(
            interface, src6, dst6, NXT_DST, hdr->pkt + 40 + offset,
            hdr->pkt_len - 40 - offset,
            hdr->pkt_len > fragsize
                ? fragsize
                : (((hdr->pkt_len - 40 - 14) / 16) + 1) * 8) < 0)
      return -1;
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ICMP6, ICMP6_PINGREPLY, NXT_ICMP6,
                        ICMP6_PINGREPLY, 100, 0, bla))
      tests[count] = 1;
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: 2 destination headers\t\t\t", count);
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    memset(bla, count % 256, sizeof(bla));
    memset(buf, 0, sizeof(buf));
    buf[0] = NXT_IGNORE;
    buf[1] = 0;
    for (i = 0; i < 2; i++)
      if (thc_add_hdr_dst(pkt, &pkt_len, (unsigned char *)&buf, 6) < 0)
        return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, 150, 0);
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ICMP6, ICMP6_PINGREPLY, NXT_ICMP6,
                        ICMP6_PINGREPLY, 130, 0, bla))
      tests[count] = 1;
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: 128 destination headers\t\t", count);
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    memset(bla, count % 256, sizeof(bla));
    memset(buf, 0, sizeof(buf));
    buf[0] = NXT_IGNORE;
    buf[1] = 0;
    for (i = 0; i < 128; i++)
      if (thc_add_hdr_dst(pkt, &pkt_len, (unsigned char *)&buf, 6) < 0)
        return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, 150, 0);
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ICMP6, ICMP6_PINGREPLY, NXT_ICMP6,
                        ICMP6_PINGREPLY, 130, 1200, bla))
      tests[count] = 1;
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: 2000 destination headers\t\t", count);
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    memset(bla, count % 256, sizeof(bla));
    memset(buf, 0, sizeof(buf));
    buf[0] = NXT_IGNORE;
    buf[1] = 0;
    for (i = 0; i < 2000; i++)
      if (thc_add_hdr_dst(pkt, &pkt_len, (unsigned char *)&buf, 6) < 0)
        return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, 150, 0);
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    hdr = (thc_ipv6_hdr *)pkt;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_send_as_fragment6(
            interface, src6, dst6, NXT_DST, hdr->pkt + 40 + offset,
            hdr->pkt_len - 40 - offset,
            hdr->pkt_len > fragsize
                ? fragsize
                : (((hdr->pkt_len - 40 - 14) / 16) + 1) * 8) < 0)
      return -1;
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ICMP6, ICMP6_PINGREPLY, NXT_ICMP6,
                        ICMP6_PINGREPLY, 130, 1200, bla))
      tests[count] = 1;
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: 8172 destination headers\t\t", count);
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    memset(bla, count % 256, sizeof(bla));
    memset(buf, 0, sizeof(buf));
    buf[0] = NXT_IGNORE;
    buf[1] = 0;
    for (i = 0; i < 8172; i++)
      if (thc_add_hdr_dst(pkt, &pkt_len, (unsigned char *)&buf, 6) < 0)
        return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, 150, 0);
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    hdr = (thc_ipv6_hdr *)pkt;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_send_as_fragment6(
            interface, src6, dst6, NXT_DST, hdr->pkt + 40 + offset,
            hdr->pkt_len - 40 - offset,
            hdr->pkt_len > fragsize
                ? fragsize
                : (((hdr->pkt_len - 40 - 14) / 16) + 1) * 8) < 0)
      return -1;
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ICMP6, ICMP6_PINGREPLY, NXT_ICMP6,
                        ICMP6_PINGREPLY, 130, 1200, bla))
      tests[count] = 1;
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: correct fragmentation\t\t\t", count);
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    memset(bla, count % 256, sizeof(bla));
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, sizeof(bla), 0);
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    hdr = (thc_ipv6_hdr *)pkt;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_send_as_fragment6(
            interface, src6, dst6, NXT_ICMP6, hdr->pkt + 40 + offset,
            hdr->pkt_len - 40 - offset,
            hdr->pkt_len > fragsize
                ? fragsize
                : (((hdr->pkt_len - 40 - 14) / 16) + 1) * 8) < 0)
      return -1;
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_FRAG, NXT_ICMP6, NXT_FRAG, NXT_ICMP6,
                        fragsize - 100, 0, bla))
      tests[count] = 1;
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: one-shot fragmentation\t\t\t", count);
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    if (thc_add_hdr_oneshotfragment(pkt, &pkt_len, getpid() + 70000) < 0)
      return -1;
    memset(bla, count % 256, sizeof(bla));
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, fragsize - 100, 0);
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    //    hdr = (thc_ipv6_hdr *) pkt;
    //    while (thc_pcap_check(p, (char *) ignoreit, NULL) > 0);
    //    if (thc_send_as_fragment6(interface, src6, dst6, NXT_ICMP6,
    //                              hdr->pkt + 40 + offset, hdr->pkt_len - 40 -
    //                              offset, hdr->pkt_len > fragsize ? fragsize :
    //                              (((hdr->pkt_len - 40 - 14) / 16) + 1) * 8) <
    //                              0)
    //      return -1;
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ICMP6, ICMP6_PINGREPLY, NXT_ICMP6,
                        ICMP6_PINGREPLY, fragsize - 200, 0, bla))
      tests[count] = 1;
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: too large fragmentation EH\t\t", count);
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    memset(bla, count % 256, sizeof(bla));
    bla[0] = 0;
    bla[1] = 0;
    bla[6] = 0x80;  // this is for wireshark this error EH not correctly
    if (thc_add_hdr_misc(pkt, &pkt_len, NXT_FRAG, -1, bla, 8 + 8 + 8 + 6) < 0)
      return -1;
    memset(bla, count % 256, sizeof(bla));
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, fragsize - 100, 0);
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    //    hdr = (thc_ipv6_hdr *) pkt;
    //    while (thc_pcap_check(p, (char *) ignoreit, NULL) > 0);
    //    if (thc_send_as_fragment6(interface, src6, dst6, NXT_ICMP6,
    //                              hdr->pkt + 40 + offset, hdr->pkt_len - 40 -
    //                              offset, hdr->pkt_len > fragsize ? fragsize :
    //                              (((hdr->pkt_len - 40 - 14) / 16) + 1) * 8) <
    //                              0)
    //      return -1;
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ICMP6, ICMP6_PINGREPLY, NXT_ICMP6,
                        ICMP6_PINGREPLY, fragsize - 200, 0, bla))
      tests[count] = 1;
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: overlap-first-zero fragmentation\t", count);
    memset(bla, count % 256, sizeof(bla));
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    memset(buf, 0, sizeof(buf));
    buf[0] = NXT_IGNORE;
    buf[1] = 0;
    if (thc_add_hdr_dst(pkt, &pkt_len, (unsigned char *)&buf, 6) < 0) return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, srcmtu - 150, 0);
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    if ((pkt2 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len2,
                                         src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    if (thc_add_hdr_dst(pkt2, &pkt_len2, (unsigned char *)&buf, 6) < 0)
      return -1;
    thc_add_icmp6(pkt2, &pkt_len2, ICMP6_PINGREPLY, 0, count,
                  (unsigned char *)&bla, srcmtu - 150, 0);
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt2, &pkt_len2) < 0)
      return -1;

    /* frag stuff */
    hdr = (thc_ipv6_hdr *)pkt;
    i = ((hdr->pkt_len - 40 - offset - 10) / 8) * 8;
    if ((pkt3 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len3,
                                         src6, dst6, 0, 0, count, 0, 0)) ==
        NULL)
      return -1;
    if (thc_add_hdr_fragment(pkt3, &pkt_len3, 0, 1, count)) return -1;
    memcpy(buf, hdr->pkt + 40 + offset, hdr->pkt_len - 40 - offset);
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_add_data6(pkt3, &pkt_len3, NXT_HDR, buf,
                      hdr->pkt_len - 40 - offset - 22))
      return -1;
    thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3,
                              &pkt_len3);  // ignore
    pkt3 = thc_destroy_packet(pkt3);
    hdr = (thc_ipv6_hdr *)pkt2;
    if ((pkt3 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len3,
                                         src6, dst6, 0, 0, count, 0, 0)) ==
        NULL)
      return -1;
    if (thc_add_hdr_fragment(pkt3, &pkt_len3, 0, 0, count)) return -1;
    memcpy(buf, hdr->pkt + 40 + offset, hdr->pkt_len - 40 - offset);
    if (thc_add_data6(pkt3, &pkt_len3, NXT_HDR, buf,
                      hdr->pkt_len - 40 - offset - 22))
      return -1;
    thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3,
                              &pkt_len3);  // ignore
    pkt3 = thc_destroy_packet(pkt3);

    /* lets see if it worked */
    pkt = thc_destroy_packet(pkt);
    pkt2 = thc_destroy_packet(pkt2);
    if (check_for_reply(p, NXT_ICMP6, ICMP6_PINGREPLY, NXT_ICMP6,
                        ICMP6_PINGREPLY, fragsize - 200, 0, bla))
      tests[count] = 1;
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: overlap-last-zero fragmentation\t", count);
    memset(bla, count % 256, sizeof(bla));
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    memset(buf, 0, sizeof(buf));
    buf[0] = NXT_IGNORE;
    buf[1] = 0;
    if (thc_add_hdr_dst(pkt, &pkt_len, (unsigned char *)&buf, 6) < 0) return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, srcmtu - 150, 0);
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    if ((pkt2 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len2,
                                         src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    if (thc_add_hdr_dst(pkt2, &pkt_len2, (unsigned char *)&buf, 6) < 0)
      return -1;
    thc_add_icmp6(pkt2, &pkt_len2, ICMP6_PINGREPLY, 0, count,
                  (unsigned char *)&bla, srcmtu - 150, 0);
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt2, &pkt_len2) < 0)
      return -1;

    /* frag stuff */
    hdr = (thc_ipv6_hdr *)pkt2;
    i = ((hdr->pkt_len - 40 - offset - 10) / 8) * 8;
    if ((pkt3 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len3,
                                         src6, dst6, 0, 0, count, 0, 0)) ==
        NULL)
      return -1;
    if (thc_add_hdr_fragment(pkt3, &pkt_len3, 0, 1, count)) return -1;
    memcpy(buf, hdr->pkt + 40 + offset, hdr->pkt_len - 40 - offset);
    if (thc_add_data6(pkt3, &pkt_len3, NXT_HDR, buf,
                      hdr->pkt_len - 40 - offset - 22))
      return -1;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3,
                              &pkt_len3);  // ignore
    pkt3 = thc_destroy_packet(pkt3);
    hdr = (thc_ipv6_hdr *)pkt;
    if ((pkt3 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len3,
                                         src6, dst6, 0, 0, count, 0, 0)) ==
        NULL)
      return -1;
    if (thc_add_hdr_fragment(pkt3, &pkt_len3, 0, 0, count)) return -1;
    memcpy(buf, hdr->pkt + 40 + offset, hdr->pkt_len - 40 - offset);
    if (thc_add_data6(pkt3, &pkt_len3, NXT_HDR, buf,
                      hdr->pkt_len - 40 - offset - 22))
      return -1;
    thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3,
                              &pkt_len3);  // ignore
    pkt3 = thc_destroy_packet(pkt3);

    /* lets see if it worked */
    pkt = thc_destroy_packet(pkt);
    pkt2 = thc_destroy_packet(pkt2);
    if (check_for_reply(p, NXT_ICMP6, ICMP6_PINGREPLY, NXT_ICMP6,
                        ICMP6_PINGREPLY, fragsize - 200, 0, bla))
      tests[count] = 1;
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: overlap-first-dst fragmentation\t", count);
    memset(bla, count % 256, sizeof(bla));
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    memset(buf, 0, sizeof(buf));
    buf[0] = NXT_IGNORE;
    buf[1] = 0;
    if (thc_add_hdr_dst(pkt, &pkt_len, (unsigned char *)&buf, 6) < 0) return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, srcmtu - 150, 0);
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    if ((pkt2 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len2,
                                         src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    if (thc_add_hdr_dst(pkt2, &pkt_len2, (unsigned char *)&buf, 6) < 0)
      return -1;
    thc_add_icmp6(pkt2, &pkt_len2, ICMP6_PINGREPLY, 0, count,
                  (unsigned char *)&bla, srcmtu - 150, 0);
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt2, &pkt_len2) < 0)
      return -1;

    /* frag stuff */
    hdr = (thc_ipv6_hdr *)pkt;
    i = ((hdr->pkt_len - 40 - offset - 10) / 8) * 8;
    if ((pkt3 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len3,
                                         src6, dst6, 0, 0, count, 0, 0)) ==
        NULL)
      return -1;
    if (thc_add_hdr_fragment(pkt3, &pkt_len3, 0, 1, count)) return -1;
    memcpy(buf, hdr->pkt + 40 + offset, hdr->pkt_len - 40 - offset);
    if (thc_add_data6(pkt3, &pkt_len3, NXT_DST, buf,
                      hdr->pkt_len - 40 - offset - 22))
      return -1;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3,
                              &pkt_len3);  // ignore
    pkt3 = thc_destroy_packet(pkt3);
    hdr = (thc_ipv6_hdr *)pkt2;
    if ((pkt3 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len3,
                                         src6, dst6, 0, 0, count, 0, 0)) ==
        NULL)
      return -1;
    if (thc_add_hdr_fragment(pkt3, &pkt_len3, 1, 0, count)) return -1;
    memcpy(buf, hdr->pkt + 40 + offset, hdr->pkt_len - 40 - offset);
    if (thc_add_data6(pkt3, &pkt_len3, NXT_DST, buf + 8,
                      hdr->pkt_len - 40 - offset - 22))
      return -1;
    thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3,
                              &pkt_len3);  // ignore
    pkt3 = thc_destroy_packet(pkt3);

    /* lets see if it worked */
    pkt = thc_destroy_packet(pkt);
    pkt2 = thc_destroy_packet(pkt2);
    if (check_for_reply(p, NXT_ICMP6, ICMP6_PINGREPLY, NXT_ICMP6,
                        ICMP6_PINGREPLY, fragsize - 200, 0, bla))
      tests[count] = 1;
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: overlap-last-dst fragmentation\t\t", count);
    memset(bla, count % 256, sizeof(bla));
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    memset(buf, 0, sizeof(buf));
    buf[0] = NXT_IGNORE;
    buf[1] = 0;
    if (thc_add_hdr_dst(pkt, &pkt_len, (unsigned char *)&buf, 6) < 0) return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, srcmtu - 150, 0);
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    if ((pkt2 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len2,
                                         src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    if (thc_add_hdr_dst(pkt2, &pkt_len2, (unsigned char *)&buf, 6) < 0)
      return -1;
    thc_add_icmp6(pkt2, &pkt_len2, ICMP6_PINGREPLY, 0, count,
                  (unsigned char *)&bla, srcmtu - 150, 0);
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt2, &pkt_len2) < 0)
      return -1;

    /* frag stuff */
    hdr = (thc_ipv6_hdr *)pkt2;
    i = ((hdr->pkt_len - 40 - offset - 10) / 8) * 8;
    if ((pkt3 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len3,
                                         src6, dst6, 0, 0, count, 0, 0)) ==
        NULL)
      return -1;
    if (thc_add_hdr_fragment(pkt3, &pkt_len3, 0, 1, count)) return -1;
    memcpy(buf, hdr->pkt + 40 + offset, hdr->pkt_len - 40 - offset);
    if (thc_add_data6(pkt3, &pkt_len3, NXT_DST, buf,
                      hdr->pkt_len - 40 - offset - 22))
      return -1;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3,
                              &pkt_len3);  // ignore
    pkt3 = thc_destroy_packet(pkt3);
    hdr = (thc_ipv6_hdr *)pkt;
    if ((pkt3 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len3,
                                         src6, dst6, 0, 0, count, 0, 0)) ==
        NULL)
      return -1;
    if (thc_add_hdr_fragment(pkt3, &pkt_len3, 1, 0, count)) return -1;
    memcpy(buf, hdr->pkt + 40 + offset, hdr->pkt_len - 40 - offset);
    if (thc_add_data6(pkt3, &pkt_len3, NXT_DST, buf + 8,
                      hdr->pkt_len - 40 - offset - 22))
      return -1;
    thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3,
                              &pkt_len3);  // ignore
    pkt3 = thc_destroy_packet(pkt3);

    /* lets see if it worked */
    pkt = thc_destroy_packet(pkt);
    pkt2 = thc_destroy_packet(pkt2);
    if (check_for_reply(p, NXT_ICMP6, ICMP6_PINGREPLY, NXT_ICMP6,
                        ICMP6_PINGREPLY, fragsize - 200, 0, bla))
      tests[count] = 1;
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: source-routing (done)\t\t\t", count);
    memset(bla, count % 256, sizeof(bla));
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    routers[0] = src6;  // route via ourself, but
    routers[1] = NULL;  // telling the target that this was already performed
    if (thc_add_hdr_route(pkt, &pkt_len, routers, 0) < 0) return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, 150, 0);
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    pkt = thc_destroy_packet(pkt);
    if ((k = check_for_reply(p, NXT_ROUTE, NXT_ICMP6, NXT_ICMP6,
                             ICMP6_PINGREPLY, 100, 0, bla))) {
      tests[count] = 1;
      if (k == 2 && use_srcroute_type < 0) use_srcroute_type = count;
    }
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: source-routing (todo)\t\t\t", count);
    memset(bla, count % 256, sizeof(bla));
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    routers[0] = src6;  // route via ourself, and
    routers[1] =
        NULL;  // telling the target that this was NOT already performed
    if (thc_add_hdr_route(pkt, &pkt_len, routers, 1) < 0) return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, 150, 0);
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    pkt = thc_destroy_packet(pkt);
    if ((k = check_for_reply(p, NXT_ROUTE, NXT_ICMP6, NXT_ICMP6,
                             ICMP6_PINGREPLY, 100, 200, bla))) {
      tests[count] = 1;
      if (k == 2 && use_srcroute_type < 0) use_srcroute_type = count;
    }
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: unauth mobile source-route\t\t", count);
    memset(bla, count % 256, sizeof(bla));
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    if (thc_add_hdr_mobileroute(pkt, &pkt_len, src6) < 0) return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, 150, 0);
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ROUTE, NXT_ICMP6, NXT_ICMP6, ICMP6_PINGREPLY,
                        100, 200, bla))  // XXX TODO: NOT SURE!
      tests[count] = 1;
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: mobile+source-routing (done)\t\t", count);
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    memset(bla, 0, sizeof(bla));
    bla[0] = 2;
    bla[1] = 1;
    memcpy(bla + 6, src6, 16);
    // 22 type, 23 routingptr, 24 reserved, 25-27 loose source routing
    memcpy(bla + 6 + 16 + 6, src6, 16);
    if (thc_add_hdr_misc(pkt, &pkt_len, NXT_ROUTE, -1, bla, 44) < 0) return -1;
    memset(bla, count % 256, sizeof(bla));
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, 150, 0);
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    pkt = thc_destroy_packet(pkt);
    if ((k = check_for_reply(p, NXT_ROUTE, NXT_ICMP6, NXT_ICMP6,
                             ICMP6_PINGREPLY, 100, 200, bla))) {
      tests[count] = 1;
      if (k == 2 && use_srcroute_type < 0) use_srcroute_type = count;
    }
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: fragmentation source-route (done)\t", count);
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    memset(bla, count % 256, sizeof(bla));
    routers[0] = src6;  // route via ourself, but
    routers[1] = NULL;  // telling the target that this was already performed
    if (thc_add_hdr_route(pkt, &pkt_len, routers, 0) < 0) return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, 1220, 0);
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    hdr = (thc_ipv6_hdr *)pkt;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_send_as_fragment6(
            interface, src6, dst6, NXT_ROUTE, hdr->pkt + 40 + offset,
            hdr->pkt_len - 40 - offset,
            hdr->pkt_len > fragsize
                ? fragsize
                : (((hdr->pkt_len - 40 - offset) / 16) + 1) * 8) < 0)
      return -1;
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ROUTE, NXT_ICMP6, NXT_ICMP6, ICMP6_PINGREPLY,
                        250, 0, bla))
      tests[count] = 1;
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: fragmentation source-route (todo)\t", count);
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    memset(bla, count % 256, sizeof(bla));
    routers[0] = src6;  // route via ourself, but
    routers[1] = NULL;  // telling the target that this was not performed yet
    if (thc_add_hdr_route(pkt, &pkt_len, routers, 1) < 0) return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, 1220, 0);
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    hdr = (thc_ipv6_hdr *)pkt;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_send_as_fragment6(
            interface, src6, dst6, NXT_ROUTE, hdr->pkt + 40 + offset,
            hdr->pkt_len - 40 - offset,
            hdr->pkt_len > fragsize
                ? fragsize
                : (((hdr->pkt_len - 40 - offset) / 16) + 1) * 8) < 0)
      return -1;
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ROUTE, NXT_ICMP6, NXT_ICMP6, ICMP6_PINGREPLY,
                        250, 0, bla))
      tests[count] = 1;
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: hop-by-hop fragmentation source-route\t", count);
    memset(bla, count % 256, sizeof(bla));
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    routers[0] = src6;  // route via ourself, but
    routers[1] = NULL;  // telling the target that this was already performed
    if (thc_add_hdr_route(pkt, &pkt_len, routers, 0) < 0) return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, srcmtu - 150, 0);
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;

    /* frag stuff */
    hdr = (thc_ipv6_hdr *)pkt;
    i = ((hdr->pkt_len - 40 - offset - 10) / 8) * 8;
    if ((pkt3 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len3,
                                         src6, dst6, 0, 0, count, 0, 0)) ==
        NULL)
      return -1;
    memset(buf, 0, sizeof(buf));
    buf[0] = NXT_IGNORE;
    buf[1] = 0;
    if (thc_add_hdr_hopbyhop(pkt3, &pkt_len3, (unsigned char *)&buf, 6) < 0)
      return -1;
    if (thc_add_hdr_fragment(pkt3, &pkt_len3, 0, 0, count)) return -1;
    memcpy(buf, hdr->pkt + 40 + offset, hdr->pkt_len - 40 - offset);
    if (thc_add_data6(pkt3, &pkt_len3, NXT_ROUTE, buf,
                      hdr->pkt_len - 40 - offset))
      return -1;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3,
                              &pkt_len3);  // ignore
    pkt3 = thc_destroy_packet(pkt3);

    /* lets see if it worked */
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ROUTE, NXT_ICMP6, NXT_ICMP6, ICMP6_PINGREPLY,
                        fragsize - 200, 0, bla))
      tests[count] = 1;
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: destination fragmentation source-route\t", count);
    memset(bla, count % 256, sizeof(bla));
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    routers[0] = src6;  // route via ourself, but
    routers[1] = NULL;  // telling the target that this was already performed
    if (thc_add_hdr_route(pkt, &pkt_len, routers, 0) < 0) return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, srcmtu - 150, 0);
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;

    /* frag stuff */
    hdr = (thc_ipv6_hdr *)pkt;
    i = ((hdr->pkt_len - 40 - offset - 10) / 8) * 8;
    if ((pkt3 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len3,
                                         src6, dst6, 0, 0, count, 0, 0)) ==
        NULL)
      return -1;
    memset(buf, 0, sizeof(buf));
    buf[0] = NXT_IGNORE;
    buf[1] = 0;
    if (thc_add_hdr_dst(pkt3, &pkt_len3, (unsigned char *)&buf, 6) < 0)
      return -1;
    if (thc_add_hdr_fragment(pkt3, &pkt_len3, 0, 0, count)) return -1;
    memcpy(buf, hdr->pkt + 40 + offset, hdr->pkt_len - 40 - offset);
    if (thc_add_data6(pkt3, &pkt_len3, NXT_ROUTE, buf,
                      hdr->pkt_len - 40 - offset))
      return -1;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3,
                              &pkt_len3);  // ignore
    pkt3 = thc_destroy_packet(pkt3);

    /* lets see if it worked */
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ROUTE, NXT_ICMP6, NXT_ICMP6, ICMP6_PINGREPLY,
                        1000, 0, bla))
      tests[count] = 1;
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: fragmentation hop-by-hop source-route\t", count);
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    memset(bla, count % 256, sizeof(bla));
    memset(buf, 0, sizeof(buf));
    buf[0] = NXT_IGNORE;
    buf[1] = 0;
    if (thc_add_hdr_hopbyhop(pkt, &pkt_len, (unsigned char *)&buf, 6) < 0)
      return -1;
    routers[0] = src6;  // route via ourself, but
    routers[1] = NULL;  // telling the target that this was already performed
    if (thc_add_hdr_route(pkt, &pkt_len, routers, 0) < 0) return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, 1220, 0);
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    hdr = (thc_ipv6_hdr *)pkt;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_send_as_fragment6(
            interface, src6, dst6, NXT_HDR, hdr->pkt + 40 + offset,
            hdr->pkt_len - 40 - offset,
            hdr->pkt_len > fragsize
                ? fragsize
                : (((hdr->pkt_len - 40 - offset) / 16) + 1) * 8) < 0)
      return -1;
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ROUTE, NXT_ICMP6, NXT_ICMP6, ICMP6_PINGREPLY,
                        250, 0, bla))
      tests[count] = 1;
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: fragmentation destination source-route\t", count);
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    memset(bla, count % 256, sizeof(bla));
    memset(buf, 0, sizeof(buf));
    buf[0] = NXT_IGNORE;
    buf[1] = 0;
    if (thc_add_hdr_dst(pkt, &pkt_len, (unsigned char *)&buf, 6) < 0) return -1;
    routers[0] = src6;  // route via ourself, but
    routers[1] = NULL;  // telling the target that this was already performed
    if (thc_add_hdr_route(pkt, &pkt_len, routers, 0) < 0) return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, 1220, 0);
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    hdr = (thc_ipv6_hdr *)pkt;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_send_as_fragment6(
            interface, src6, dst6, NXT_DST, hdr->pkt + 40 + offset,
            hdr->pkt_len - 40 - offset,
            hdr->pkt_len > fragsize
                ? fragsize
                : (((hdr->pkt_len - 40 - offset) / 16) + 1) * 8) < 0)
      return -1;
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ROUTE, NXT_ICMP6, NXT_ICMP6, ICMP6_PINGREPLY,
                        250, 0, bla))
      tests[count] = 1;
  }
  count++;

  /*** misc icmp solicitations ***/

  if (test == 0 || test == count) {
    printf("Test %2d: node information\t\t\t", count);
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    memset(buf, 0, sizeof(buf));
    memcpy(buf, (char *)&count + _TAKE4, 4);
    memcpy(buf + 4, (char *)&count + _TAKE4, 4);
    memcpy(buf + 8, dst6, 16);
    thc_add_icmp6(pkt, &pkt_len, ICMP6_INFOREQUEST, 0, 0x00030000,
                  (unsigned char *)&buf, 24, 0);
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ICMP6, ICMP6_INFOREPLY, NXT_ICMP6,
                        ICMP6_INFOREPLY, 0, 0, NULL))
      tests[count] = 1;
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: inverse neighbor solicitation\t\t", count);
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    memset(buf, 0, sizeof(buf));
    buf[0] = 0x01;
    buf[1] = 0x01;
    memcpy(buf + 2, srcmac, 6);
    buf[8] = 0x02;
    buf[9] = 0x01;
    memcpy(buf + 10, dstmac, 6);
    thc_add_icmp6(pkt, &pkt_len, ICMP6_INVNEIGHBORSOL, 0, 0,
                  (unsigned char *)&buf, 16, 0);
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ICMP6, ICMP6_INVNEIGHBORADV, NXT_ICMP6,
                        ICMP6_INVNEIGHBORADV, 0, 0, NULL))
      tests[count] = 1;
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: mobile prefix solicitation\t\t", count);
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    memset(buf, 0, sizeof(buf));
    buf[0] = 0xc9;
    buf[1] = 16;
    memcpy(buf + 2, src6, 16);
    if (thc_add_hdr_dst(pkt, &pkt_len, (unsigned char *)&buf, 18) < 0)
      return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_MOBILE_PREFIXSOL, 0, count << 16,
                  (unsigned char *)&buf, 18, 0);
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ICMP6, ICMP6_MOBILE_PREFIXADV, NXT_ICMP6,
                        ICMP6_MOBILE_PREFIXADV, 0, 0, NULL))
      tests[count] = 1;
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: certificate solicitation\t\t", count);
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    i = count << 16;
    i += 0xffff;
    memset(buf, 0, sizeof(buf));
    buf[0] = 15;
    buf[1] = 8;
    buf[2] = 1;
    buf[3] = 4;
    buf[4] = 1;
    buf[5] = '.';
    thc_add_icmp6(pkt, &pkt_len, ICMP6_CERTPATHSOL, 0, i, (unsigned char *)&buf,
                  10, 0);
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ICMP6, ICMP6_CERTPATHADV, NXT_ICMP6,
                        ICMP6_CERTPATHADV, 0, 0, NULL))
      tests[count] = 1;
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: ping6 with a zero AH extension header\t", count);
    memset(bla, count % 256, sizeof(bla));
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    memset(buf, 0, sizeof(buf));
    if (thc_add_hdr_misc(pkt, &pkt_len, NXT_AH, -1, (unsigned char *)&buf, 14) <
        0)
      return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, 150, 0);
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    hdr = (thc_ipv6_hdr *)pkt;
    if (do_hdr_size != 0)
      hdr->pkt[do_hdr_size + 40 + 1] = 2;
    else
      hdr->pkt[14 + 40 + 1] = 2;
    thc_send_pkt(interface, pkt, &pkt_len);
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ICMP6, ICMP6_PINGREPLY, NXT_ICMP6,
                        ICMP6_PINGREPLY, 130, 0, bla))
      tests[count] = 1;
  }
  count++;

  /* */
  if (test == 0 || test == count) {
    printf("Test %2d: TCP-SYN(1) with a zero AH extension header\t", count);
    memset(bla, count % 256, sizeof(bla));
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    memset(buf, 0, sizeof(buf));
    if (thc_add_hdr_misc(pkt, &pkt_len, NXT_AH, -1, (unsigned char *)&buf, 6) <
        0)
      return -1;
    thc_add_tcp(pkt, &pkt_len, 1, 1, 1, 0, TCP_SYN, 5760, 0, NULL, 0, NULL, 0);
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ICMP6, ICMP6_PINGREPLY, NXT_ICMP6,
                        ICMP6_PINGREPLY, 130, 0, bla))
      tests[count] = 1;
  }
  count++;

  /* */
  if (test == 0 || test == count) {
    printf("Test %2d: extension header with two bytes of ping6\t", count);
    memset(bla, count % 256, sizeof(bla));
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    memset(buf, 0, sizeof(buf));
    if (thc_add_hdr_misc(pkt, &pkt_len, NXT_DST, -1, (unsigned char *)&buf, 6) <
        0)
      return -1;
    bla[0] = 128;
    bla[1] = 0;
    if (thc_add_data6(pkt, &pkt_len, NXT_ICMP6, (unsigned char *)&bla, 2) < 0)
      return -1;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ICMP6, ICMP6_PINGREPLY, NXT_ICMP6,
                        ICMP6_PINGREPLY, 130, 0, bla))
      tests[count] = 1;
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: ping6 with a zero ESP extension header\t", count);
    memset(bla, count % 256, sizeof(bla));
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    memset(buf, 0, sizeof(buf));
    if (thc_add_hdr_misc(pkt, &pkt_len, NXT_ESP, -1, (unsigned char *)&buf, 6) <
        0)
      return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, 150, 0);
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ICMP6, ICMP6_PINGREPLY, NXT_ICMP6,
                        ICMP6_PINGREPLY, 130, 0, bla))
      tests[count] = 1;
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: ping from multicast (local!)\t\t", count);
    memset(bla, count % 256, sizeof(bla));
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        mcast6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, 150, 0);
    thc_pcap_close(p);
    p = thc_pcap_init(interface, string2);
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ROUTE, NXT_ICMP6, NXT_ICMP6, ICMP6_PINGREPLY,
                        100, 0, bla))
      tests[count] = 1;
    thc_pcap_close(p);
    p = thc_pcap_init(interface, string);
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: frag+source-route to link local\t", count);
    memset(bla, count % 256, sizeof(bla));
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    routers[0] = lsrc6;  // route via ourself
    routers[1] = NULL;
    if (thc_add_hdr_route(pkt, &pkt_len, routers, 1) < 0) return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, 150, 0);
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    hdr = (thc_ipv6_hdr *)pkt;
    if (thc_send_as_fragment6(
            interface, src6, dst6, NXT_ROUTE, hdr->pkt + 40 + offset,
            hdr->pkt_len - 40 - offset,
            hdr->pkt_len > fragsize
                ? fragsize
                : (((hdr->pkt_len - 40 - 14) / 16) + 1) * 8) < 0)
      return -1;
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ROUTE, NXT_ICMP6, NXT_ICMP6, ICMP6_PINGREPLY,
                        130, 0, bla))
      tests[count] = 1;
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: frag+source-route to multicast\t\t", count);
    memset(bla, count % 256, sizeof(bla));
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    routers[0] = mcast6;
    routers[1] = NULL;
    if (thc_add_hdr_route(pkt, &pkt_len, routers, 1) < 0) return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, 150, 0);
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    hdr = (thc_ipv6_hdr *)pkt;
    if (thc_send_as_fragment6(
            interface, src6, dst6, NXT_ROUTE, hdr->pkt + 40 + offset,
            hdr->pkt_len - 40 - offset,
            hdr->pkt_len > fragsize
                ? fragsize
                : (((hdr->pkt_len - 40 - 14) / 16) + 1) * 8) < 0)
      return -1;
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ROUTE, NXT_ICMP6, NXT_ICMP6, ICMP6_PINGREPLY,
                        130, 0, bla))
      tests[count] = 1;
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: frag+srcroute from link local (local!)\t", count);
    memset(bla, count % 256, sizeof(bla));
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        lsrc6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    routers[0] = src6;
    routers[1] = NULL;
    if (thc_add_hdr_route(pkt, &pkt_len, routers, 0) < 0) return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, 150, 0);
    thc_pcap_close(p);
    p = thc_pcap_init(interface, string2);
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    hdr = (thc_ipv6_hdr *)pkt;
    if (thc_send_as_fragment6(
            interface, lsrc6, dst6, NXT_ROUTE, hdr->pkt + 40 + offset,
            hdr->pkt_len - 40 - offset,
            hdr->pkt_len > fragsize
                ? fragsize
                : (((hdr->pkt_len - 40 - 14) / 16) + 1) * 8) < 0)
      return -1;
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ROUTE, NXT_ICMP6, NXT_ICMP6, ICMP6_PINGREPLY,
                        100, 0, bla))
      tests[count] = 1;
    thc_pcap_close(p);
    p = thc_pcap_init(interface, string);
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: frag+srcroute from multicast (local!)\t", count);
    memset(bla, count % 256, sizeof(bla));
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        mcast6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    routers[0] = src6;
    routers[1] = NULL;
    if (thc_add_hdr_route(pkt, &pkt_len, routers, 0) < 0) return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, 150, 0);
    thc_pcap_close(p);
    p = thc_pcap_init(interface, string2);
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    hdr = (thc_ipv6_hdr *)pkt;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_send_as_fragment6(
            interface, mcast6, dst6, NXT_ROUTE, hdr->pkt + 40 + offset,
            hdr->pkt_len - 40 - offset,
            hdr->pkt_len > fragsize
                ? fragsize
                : (((hdr->pkt_len - 40 - 14) / 16) + 1) * 8) < 0)
      return -1;
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ROUTE, NXT_ICMP6, NXT_ICMP6, ICMP6_PINGREPLY,
                        100, 0, bla))
      tests[count] = 1;
    thc_pcap_close(p);
    p = thc_pcap_init(interface, string);
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: direct neighbor solicitation\t\t", count);
    memset(bla, count % 256, sizeof(bla));
    memset(buf, 0, sizeof(buf));
    memcpy(buf, dst6, 16);
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_NEIGHBORSOL, 0, 0, (unsigned char *)&buf,
                  16, 0);
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    if (check_for_reply_n(p, src6, dst6)) tests[count] = 1;
    pkt = thc_destroy_packet(pkt);
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: direct neighbor solicitation ttl<255\t", count);
    memset(bla, count % 256, sizeof(bla));
    memset(buf, 0, sizeof(buf));
    memcpy(buf, dst6, 16);
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 63, 0, count, 0, 0)) ==
        NULL)
      return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_NEIGHBORSOL, 0, 0, (unsigned char *)&buf,
                  16, 0);
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply_n(p, src6, dst6)) tests[count] = 1;
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: filled ignore hop-by-hop option\t", count);
    memset(bla, count % 256, sizeof(bla));
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    memset(buf, 0, sizeof(buf));
    i = 0;
    for (j = 0; j < 10; j++) {
      buf[i++] = NXT_IGNORE;  // ignore, length
      buf[i++] = j;
      if (j > 0) {
        memset(buf + i, 0xaa, j);
        i += j;
      }
    }
    buf[i++] = 1;  // padN, length 2
    buf[i++] = 2;
    buf[i++] = count % 256;
    buf[i++] = count % 256;
    buf[i++] = 0;  // pad1

    if (thc_add_hdr_hopbyhop(pkt, &pkt_len, (unsigned char *)&buf, i) < 0)
      return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, 150, 0);
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ICMP6, ICMP6_PINGREPLY, NXT_ICMP6,
                        ICMP6_PINGREPLY, 140, 140 + i, bla))
      tests[count] = 1;
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: filled padding hop-by-hop option\t", count);
    memset(bla, count % 256, sizeof(bla));
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    memset(buf, 0, sizeof(buf));
    i = 0;
    for (j = 0; j < 10; j++) {
      buf[i++] = 1;  // ignore, length
      buf[i++] = j;
      if (j > 0) {
        memset(buf + i, 0, j);
        i += j;
      }
    }
    buf[i++] = 1;  // padN, length 2
    buf[i++] = 2;
    buf[i++] = 0;
    buf[i++] = 0;
    buf[i++] = 0;  // pad1

    if (thc_add_hdr_hopbyhop(pkt, &pkt_len, (unsigned char *)&buf, i) < 0)
      return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, 150, 0);
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ICMP6, ICMP6_PINGREPLY, NXT_ICMP6,
                        ICMP6_PINGREPLY, 140, 140 + i, bla))
      tests[count] = 1;
  }
  count++;

  /* Testing hop-by-hop options does not make much sense as a reply usually
     will mean that the option is known, ignored or unknown.
     // hop: jumbo     0xc2|4|SIZE|SIZE|SIZE|SIZE
     // hop: router alert 5|2|0|0
     // hop: quickstart   6|6|1|count%256|count%256|count%256|count%256|0
     (rfc4782)
     // hop: calipso
     7|16|0xff|0xff|0xff|0xff|2|0xff|crc|crc|0xff|0xff|0xff|0xff|0xff|0xff|0xff|0xff
   */

  /*
  memset(buf, 0, sizeof(buf));
  buf[0] = 7;
  buf[1] = 12;
  buf[2] = 0xff;
  buf[3] = 0xff;
  buf[4] = 0xff;
  buf[5] = 0xff;
  buf[6] = 1;
  buf[7] = 0xff;
  buf[8] = 0;
  buf[9] = 0;
  memset(buf + 10, 0xff, 8);
  i = calculate_checksum(buf, 18);
  buf[8] = i / 256;
  buf[9] = i % 256;
  */

  if (test == 0 || test == count) {
    printf("Test %2d: filled ignore destination option\t", count);
    memset(bla, count % 256, sizeof(bla));
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    memset(buf, 0, sizeof(buf));
    i = 0;
    for (j = 0; j < 10; j++) {
      buf[i++] = NXT_IGNORE;  // ignore, length
      buf[i++] = j;
      if (j > 0) {
        memset(buf + i, 0xaa, j);
        i += j;
      }
    }

    /*
        buf[i++] = 0xc9; // mobility, length 16
        buf[i++] = 16;
        memcpy(buf+i, src6, 16);
        i += 16;
        buf[i++] = 4; // tunnel max encaps, length 1
        buf[i++] = 1;
        buf[i++] = 0;
    */
    buf[i++] = 1;  // padN, length 2
    buf[i++] = 2;
    buf[i++] = count % 256;
    buf[i++] = count % 256;
    buf[i++] = 0;  // pad1

    if (thc_add_hdr_dst(pkt, &pkt_len, (unsigned char *)&buf, i) < 0) return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, 150, 0);
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ICMP6, ICMP6_PINGREPLY, NXT_ICMP6,
                        ICMP6_PINGREPLY, 140, 140 + i, bla))
      tests[count] = 1;
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: filled padding destination option\t", count);
    memset(bla, count % 256, sizeof(bla));
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    memset(buf, 0, sizeof(buf));
    i = 0;
    for (j = 0; j < 10; j++) {
      buf[i++] = 1;  // ignore, length
      buf[i++] = j;
      if (j > 0) {
        memset(buf + i, 0, j);
        i += j;
      }
    }
    buf[i++] = 1;  // padN, length 2
    buf[i++] = 2;
    buf[i++] = 0;
    buf[i++] = 0;
    buf[i++] = 0;  // pad1

    if (thc_add_hdr_dst(pkt, &pkt_len, (unsigned char *)&buf, i) < 0) return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, 150, 0);
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ICMP6, ICMP6_PINGREPLY, NXT_ICMP6,
                        ICMP6_PINGREPLY, 140, 140 + i, bla))
      tests[count] = 1;
  }
  count++;

  // dst: mobility 0xc9|0x10|src6
  // dst: tunnel max encapsulation 4|1|1

  if (test == 0 || test == count) {
    printf("Test %2d: jumbo option size < 64k\t\t", count);
    memset(bla, count % 256, sizeof(bla));
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    memset(buf, 0, sizeof(buf));
    buf[0] = 0xc2;
    buf[1] = 4;
    buf[5] = 166;
    if (thc_add_hdr_hopbyhop(pkt, &pkt_len, (unsigned char *)&buf, 6) < 0)
      return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, 150, 0);
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_send_pkt(interface, pkt, &pkt_len) < 0) return -1;
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ICMP6, ICMP6_PINGREPLY, NXT_ICMP6,
                        ICMP6_PINGREPLY, 140, 140 + i, bla))
      tests[count] = 1;
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: jumbo option size < 64k, length 0\t", count);
    memset(bla, count % 256, sizeof(bla));
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    memset(buf, 0, sizeof(buf));
    buf[0] = 0xc2;
    buf[1] = 4;
    buf[5] = 166;
    if (thc_add_hdr_hopbyhop(pkt, &pkt_len, (unsigned char *)&buf, 6) < 0)
      return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, 150, 0);
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    hdr = (thc_ipv6_hdr *)pkt;
    i = offset;
    hdr->pkt[4 + i] = 0;  // set ip length to 0
    hdr->pkt[5 + i] = 0;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_send_pkt(interface, pkt, &pkt_len) < 0) return -1;
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ICMP6, ICMP6_PINGREPLY, NXT_ICMP6,
                        ICMP6_PINGREPLY, 140, 140 + i, bla))
      tests[count] = 1;
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: error option in hop-by-hop\t\t", count);
    memset(bla, count % 256, sizeof(bla));
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    memset(buf, 0, sizeof(buf));
    buf[0] = 0xc3;
    buf[1] = 4;
    buf[5] = 166;
    if (thc_add_hdr_hopbyhop(pkt, &pkt_len, (unsigned char *)&buf, 6) < 0)
      return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, 150, 0);
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_send_pkt(interface, pkt, &pkt_len) < 0) return -1;
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ICMP6, ICMP6_PINGREPLY, NXT_ICMP6,
                        ICMP6_PINGREPLY, 140, 140 + i, bla))
      tests[count] = 1;
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: error option in dsthdr\t\t\t", count);
    memset(bla, count % 256, sizeof(bla));
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    memset(buf, 0, sizeof(buf));
    buf[0] = 0xc3;
    buf[1] = 4;
    buf[5] = 166;
    if (thc_add_hdr_dst(pkt, &pkt_len, (unsigned char *)&buf, 6) < 0) return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, 150, 0);
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_send_pkt(interface, pkt, &pkt_len) < 0) return -1;
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ICMP6, ICMP6_PINGREPLY, NXT_ICMP6,
                        ICMP6_PINGREPLY, 140, 140 + i, bla))
      tests[count] = 1;
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: 0 length field\t\t\t\t", count);
    memset(bla, count % 256, sizeof(bla));
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, 150, 0);
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    hdr = (thc_ipv6_hdr *)pkt;
    i = offset;
    hdr->pkt[4 + i] = 0;  // set ip length to 0
    hdr->pkt[5 + i] = 0;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_send_pkt(interface, pkt, &pkt_len) < 0) return -1;
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ICMP6, ICMP6_PINGREPLY, NXT_ICMP6,
                        ICMP6_PINGREPLY, 140, 140 + i, bla))
      tests[count] = 1;
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: too large length field\t\t\t", count);
    memset(bla, count % 256, sizeof(bla));
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, 150, 0);
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    hdr = (thc_ipv6_hdr *)pkt;
    i = offset;
    hdr->pkt[4 + i] = 1;  // set ip length to 0
    hdr->pkt[5 + i] = 0;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_send_pkt(interface, pkt, &pkt_len) < 0) return -1;
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ICMP6, ICMP6_PINGREPLY, NXT_ICMP6,
                        ICMP6_PINGREPLY, 140, 140 + i, bla))
      tests[count] = 1;
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: too small length field\t\t\t", count);
    memset(bla, count % 256, sizeof(bla));
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, 150, 0);
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    hdr = (thc_ipv6_hdr *)pkt;
    i = offset;
    hdr->pkt[4 + i] = 0;  // set ip length to 0
    hdr->pkt[5 + i] = 60;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_send_pkt(interface, pkt, &pkt_len) < 0) return -1;
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ICMP6, ICMP6_PINGREPLY, NXT_ICMP6,
                        ICMP6_PINGREPLY, 140, 140 + i, bla))
      tests[count] = 1;
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: ping6 with bad checksum\t\t", count);
    memset(bla, count % 256, sizeof(bla));
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, 150, 0x6666);
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ICMP6, ICMP6_PINGREPLY, NXT_ICMP6,
                        ICMP6_PINGREPLY, 100, 0, bla))
      tests[count] = 1;
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: ping6 with zero checksum\t\t", count);
    memset(bla, count % 256, sizeof(bla));
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, 150, 0x6666);
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    hdr = (thc_ipv6_hdr *)pkt;
    memset(hdr->pkt + hdr->pkt_len - 150 - 6, 0, 2);
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_send_pkt(interface, pkt, &pkt_len) < 0) return -1;
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ICMP6, ICMP6_PINGREPLY, NXT_ICMP6,
                        ICMP6_PINGREPLY, 100, 0, bla))
      tests[count] = 1;
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: ping with hop count 0\t\t\t", count);
    memset(bla, count % 256, sizeof(bla));
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, -1, 0, count, 0, 0)) ==
        NULL)
      return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla, 150, 0);
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    if (thc_send_pkt(interface, pkt, &pkt_len) < 0) return -1;
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ICMP6, ICMP6_PINGREPLY, NXT_ICMP6,
                        ICMP6_PINGREPLY, 140, 140 + i, bla))
      tests[count] = 1;
  }
  count++;

  if (test == 0 || test == count) {
    printf("Test %2d: fragment missing\t\t\t", count);
    memset(bla, count % 256, sizeof(bla));
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                        src6, dst6, 255, 0, count, 0, 0)) ==
        NULL)
      return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, count,
                  (unsigned char *)&bla,
                  sizeof(bla) > 1400 ? 1400 : sizeof(bla), 0);
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;

    /* frag stuff */
    hdr = (thc_ipv6_hdr *)pkt;
    i = ((hdr->pkt_len - 40 - offset - 10) / 8) * 8;
    if ((pkt3 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len3,
                                         src6, dst6, 0, 0, count, 0, 0)) ==
        NULL)
      return -1;
    if (thc_add_hdr_fragment(pkt3, &pkt_len3, 128, 0, count)) return -1;
    memcpy(buf, hdr->pkt + 40 + offset, hdr->pkt_len - 40 - offset);
    if (thc_add_data6(pkt3, &pkt_len3, NXT_ICMP6, buf,
                      hdr->pkt_len - 40 - offset - 22))
      return -1;
    while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
      ;
    thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt3,
                              &pkt_len3);  // ignore
    pkt3 = thc_destroy_packet(pkt3);

    /* lets see if it worked */
    pkt = thc_destroy_packet(pkt);
    if (check_for_reply(p, NXT_ICMP6, ICMP6_PINGREPLY, NXT_ICMP6,
                        ICMP6_PINGREPLY, fragsize - 200, 0, bla))
      tests[count] = 1;
  }
  count++;

  // more needed?

  /******************* END OF TESTCASES ***************************/

  if (noping == 0) {
    if (check_alive(p, interface, src6, dst6))
      printf(
          "Test %2d: normal ping6 (still alive?)\t\tPASSED - we got a reply\n",
          count);
    else
      printf(
          "Test %2d: normal ping6 (still alive?)\t\tFAILED - target is "
          "unavailable now!\n",
          count);
  }

  thc_pcap_close(p);

  return ret_code;
}
