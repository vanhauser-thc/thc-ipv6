#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <netdb.h>
#include <pcap.h>
#include "thc-ipv6.h"

#define MAX_SEND 15
#define INCREASE 8
#define SENDS 3
#define POS_SIZE ((SENDS * MAX_SEND) + 2)

unsigned char *    position[POS_SIZE];
unsigned char *    remark[POS_SIZE];
unsigned int       rmtu[POS_SIZE];
unsigned char      buf2[4];
unsigned short int baseport = 1200;
unsigned int       pid = 0;
unsigned int       mtu = 0;
unsigned int       orig_mtu = 0;
int udp = 0, offset = 48, buf_len = 16, tunnel = 0, do_alert = 0, do_reply = 0,
    do_toobig = 0, do_frag = 0, do_dst = 0, do_dst2 = 0;
int up_to = MAX_SEND, complete = 0, type = 0, rawmode = 0, finaldst = 0;

void help(char *prg) {
  printf("%s %s (c) 2022 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf("Syntax: %s [-abdtu] [-s src6] interface targetaddress [port]\n\n",
         prg);
  printf("Options:\n");
  printf("  -a       insert a hop-by-hop header with router alert option.\n");
  printf("  -D       insert a destination extension header\n");
  printf(
      "  -E       insert a destination extension header with an invalid "
      "option\n");
  printf("  -F       insert a one-shot fragmentation header\n");
  printf(
      "  -b       instead of an ICMP6 Ping, use TooBig (you will not see the "
      "target)\n");
  printf(
      "  -B       instead of an ICMP6 Ping, use PingReply (you will not see "
      "the target)\n");
  printf("  -d       resolves the IPv6 addresses to DNS.\n");
  printf("  -t       enables tunnel detection\n");
  printf("  -u       use UDP instead of TCP if a port is supplied\n");
  printf("  -r       raw mode (for adapters networks that have no ethernet)\n");
  printf("  -s src6  specifies the source IPv6 address\n");
  printf("Maximum hop reach: %d\n\n", INCREASE * (SENDS - 1) + MAX_SEND);
  printf("A basic but very fast traceroute6 program.\n");
  printf(
      "If no port is specified, ICMP6 Ping requests are used, otherwise TCP "
      "SYN\n");
  printf(
      "packets to the specified port. Options D, E and F can be use multiple "
      "times.\n");
  exit(-1);
}

void check_packets(u_char *foo, const struct pcap_pkthdr *header,
                   const unsigned char *data) {
  int                 i, ok = 0, len = header->caplen, add, add2;
  unsigned char *     ptr = (unsigned char *)data, *ptr2;
  unsigned short int *si;
  unsigned int *      ui, new_mtu = 0;
  unsigned char       pos = 0, pos2;

  if (!rawmode) {
    ptr += 14;
    len -= 14;
  }
  if (do_hdr_size) {
    ptr += (do_hdr_size - 14);
    len -= (do_hdr_size - 14);
    if ((ptr[0] & 240) != 0x60) return;
  }
  add = do_alert + do_frag + do_dst;
  add2 = do_alert + do_dst;

  if (debug) thc_dump_data(ptr, len, "Received Packet");
  complete = 0;

  if (tunnel && ptr[6] == NXT_ICMP6 && ptr[40] == ICMP6_TOOBIG && len >= 100) {
    new_mtu = (ptr[44] << 24) + (ptr[45] << 16) + (ptr[46] << 8) + ptr[47];
    if (new_mtu < mtu) {
      if (type != 2) {
        pos = ptr[94 + 8 * (add)];
        pos2 = ptr[93 + 8 * (add)];
        if (pos != pos2 || pos > up_to) {
          pos = ptr[94 + 8 * (add2)];
          pos2 = ptr[93 + 8 * (add2)];
        }
      } else {
        pos = ptr[101 + 0x30 + 8 * (add + do_toobig - 1)];
        pos2 = ptr[100 + 0x30 + 8 * (add + do_toobig - 1)];
      }
      if (pos == pos2 && pos <= up_to) {
        rmtu[pos - 1] = new_mtu;
        mtu = new_mtu;
        buf_len = mtu - offset;
      }
    }
  }

  if (type != 1) {
    if (ptr[6] != NXT_ICMP6) return;
    if (ptr[40] == ICMP6_PINGREPLY) {
      ptr2 = ptr + 48;
      if (memcmp(ptr + 48, buf2, 4) != 0)  // from a different process?
        return;
      pos = ptr[46];
      if (position[pos] != NULL && pos <= up_to && pos == ptr[45]) {
        if (position[pos] != NULL) {
          position[pos] = thc_ipv62notation(ptr + 8);
          remark[pos] = strdup("\t[ping reply received]");
        }
        position[pos + 1] = NULL;
        finaldst = 1;
      }
    } else {
      // now for the error icmp types
      if (type == 0)
        ptr2 = ptr + 96 + 8 * (add);
      else
        ptr2 = ptr + 104 + 0x30 + 8 * (add);
      if (memcmp(ptr2, buf2, 4) != 0)  // from a different process?
        return;
      if (ptr[40] == ICMP6_TTLEXEED && ptr[41] == 0 && len >= 100) {
        if (type == 0) {
          pos = ptr[94 + 8 * (add)];
          pos2 = ptr[93 + 8 * (add)];
          if (pos != pos2 || pos > up_to) {
            pos = ptr[94 + 8 * (add2)];
            pos2 = ptr[93 + 8 * (add2)];
          }
          // printf("Exceed from %s\n", thc_ipv62notation(ptr + 8));
          // printf(" POS1 is : 94 + 8*(add) = [%d] <= %d ?\n", pos, up_to);
          // printf(" POS2 is : 93 + 8*(add) = [%d] <= %d ?\n", pos2, up_to);
        } else {
          pos = ptr[101 + 0x30 + 8 * (add + do_toobig - 1)];
          pos2 = ptr[100 + 0x30 + 8 * (add + do_toobig - 1)];
        }
        // printf("%d == %d < %d\n", pos, pos2, up_to);
        if (pos == pos2 && pos <= up_to)
          position[pos] = thc_ipv62notation(ptr + 8);
      }
      if (ptr[40] == ICMP6_UNREACH) {
        if (type == 0) {
          pos = ptr[94 + 8 * (add)];
          pos2 = ptr[93 + 8 * (add)];
          if (pos != pos2 || pos > up_to) {
            pos = ptr[94 + 8 * (add2)];
            pos2 = ptr[93 + 8 * (add2)];
          }
        } else {
          pos = ptr[101 + 0x30 + 8 * (add + do_toobig - 1)];
          pos2 = ptr[100 + 0x30 + 8 * (add + do_toobig - 1)];
        }
        if (pos == pos2 && pos <= up_to) {
          if (position[pos] != NULL) {
            position[pos] = thc_ipv62notation(ptr + 8);
            remark[pos] = strdup("\t[unreachable message received]");
          }
          //        if (position[pos + 1][0] == '?')
          position[pos + 1] = NULL;
        }
      }
      if (do_dst2 == 1 && ptr[40] == ICMP6_PARAMPROB) {
        if (type == 0) {
          pos = ptr[94 + 8 * (add)];
          pos2 = ptr[93 + 8 * (add)];
          if (pos != pos2 || pos > up_to) {
            pos = ptr[94 + 8 * (add2)];
            pos2 = ptr[93 + 8 * (add2)];
          }
        } else {
          pos = ptr[101 + 0x30 + 8 * (add + do_toobig - 1)];
          pos2 = ptr[100 + 0x30 + 8 * (add + do_toobig - 1)];
        }
        // thc_dump_data(ptr, len, "pkt");
        // printf("type: %d, pos %d, pos2 %d\n", type, pos, pos2);
        if (pos == pos2 && pos <= up_to) {
          if (position[pos] != NULL) {
            position[pos] = thc_ipv62notation(ptr + 8);
            remark[pos] = strdup("\t[parameter problem received]");
          }
          //        if (position[pos + 1][0] == '?')
          position[pos + 1] = NULL;
          finaldst = 1;
        }
      }
    }
  } else {
    if (ptr[6] != NXT_ICMP6 &&
        ((udp == 0 && ptr[6] != NXT_TCP) || (udp == 1 && ptr[6] != NXT_UDP)))
      return;
    if (ptr[6] == NXT_TCP) {
      si = (unsigned short int *)&ptr[42];
      pos = htons((*si % 65536)) - baseport;
      ui = (unsigned int *)&ptr[48];
      if ((pid + 1) != htonl(*ui)) return;
      if (position[pos] != NULL && pos <= up_to) {
        position[pos] = thc_ipv62notation(ptr + 8);
        i = ptr[53] & 6;
        switch (i) {
          case 2:
            remark[pos] = strdup("\t[TCP SYN-ACK reply received]");
            break;
          case 4:
            remark[pos] = strdup("\t[TCP RST reply received]");
            break;
          default:
            remark[pos] = strdup("\t[TCP unknown reply received]");
        }
        position[pos + 1] = NULL;
        finaldst = 1;
      }
    }
    if (ptr[6] == NXT_UDP) {
      si = (unsigned short int *)&ptr[42];
      pos = htons((*si % 65536)) - baseport;
      if (position[pos] != NULL && pos <= up_to) {
        position[pos] = thc_ipv62notation(ptr + 8);
        remark[pos] = strdup("\t[UDP reply received]");
        position[pos + 1] = NULL;
        finaldst = 1;
      }
    }
    if (ptr[6] == NXT_ICMP6 && ptr[40] == ICMP6_TTLEXEED && ptr[41] == 0 &&
        len >= 100) {
      si = (unsigned short int *)&ptr[88 + 8 * (add)];
      ui = (unsigned int *)&ptr[92 + 8 * (add)];
      pos = htons((*si % 65536)) - baseport;
      if (pid != htonl(*ui)) return;
      if (pos <= up_to) position[pos] = thc_ipv62notation(ptr + 8);
    }
    if (ptr[6] == NXT_ICMP6 && ptr[40] == ICMP6_UNREACH && len >= 100) {
      si = (unsigned short int *)&ptr[88 + 8 * (add)];
      ui = (unsigned int *)&ptr[92 + 8 * (add)];
      pos = htons((*si % 65536)) - baseport;
      if (pid != htonl(*ui)) return;
      if (pos <= up_to) {
        if (position[pos] != NULL) {
          position[pos] = thc_ipv62notation(ptr + 8);
          if (udp && ptr[41] == 4) {
            remark[pos] = strdup("\t[port unreachable message received]");
            position[pos + 1] = NULL;
            finaldst = 1;
          } else
            remark[pos] = strdup("\t[unreachable message received]");
        }
        // if (position[pos + 1][0] == '?')
        position[pos + 1] = NULL;
      }
    }
  }
  for (i = 1; i <= up_to && position[i] != NULL; i++) {
    if (position[i][0] != '?') ok++;
    if (position[ok + 1] == NULL) complete = 1;
  }
}

int main(int argc, char *argv[]) {
  unsigned char *pkt = NULL, *pkt2 = NULL, foomac[6];
  unsigned char *dst6, *src6 = NULL, foo6[16], *mac = NULL,
                       string[64] = "ip6 and dst ";
  int pkt_len = 0, pkt2_len = 0, i, k, m, dport = 0, resolve = 0,
      notreached = 0;
  unsigned int    j;
  struct hostent *he;
  unsigned char * interface, *srcmac, *buf = NULL, dummy[4] = "???", text[120],
                                     buf3[6];
  time_t        passed;
  pcap_t *      p;
  thc_ipv6_hdr *ipv6;

  if (argc < 3 || strncmp(argv[1], "-h", 2) == 0) help(argv[0]);

  while ((i = getopt(argc, argv, "abBdtrus:FDEX")) >= 0) {
    switch (i) {
      case 'd':
        resolve = 1;
        break;
      case 'X':
        debug = 1;
        break;
      case 'a':
        do_alert = 1;
        break;
      case 'b':
        do_toobig++;
        type = 2;
        break;
      case 'B':
        do_reply++;
        type = 2;
        break;
      case 'r':
        thc_ipv6_rawmode(1);
        rawmode = 1;
        break;
      case 't':
        tunnel = 1;
        break;
      case 'u':
        udp = 1;
        break;
      case 's':
        src6 = thc_resolve6(optarg);
        break;
      case 'F':
        do_frag++;
        break;
      case 'E':
        do_dst++;
        do_dst2 = 1;
        break;
      case 'D':
        do_dst++;
        break;
      default:
        fprintf(stderr, "Error: invalid option %c\n", i);
        exit(-1);
    }
  }

  if (argc - optind < 2) help(argv[0]);

  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  interface = argv[optind];
  if ((dst6 = thc_resolve6(argv[optind + 1])) == NULL) {
    fprintf(stderr, "Error: can not resolve %s\n", argv[optind + 1]);
    exit(-1);
  }
  if (src6 == NULL) src6 = thc_get_own_ipv6(interface, dst6, PREFER_GLOBAL);
  srcmac = thc_get_own_mac(interface);
  up_to = MAX_SEND;
  if (do_reply) do_toobig = 0;

  if (argc - optind >= 3 && argv[optind + 2] != NULL) {
    if (type) {
      fprintf(stderr,
              "Error: you can not use option -b and specify a target TCP port "
              "together\n");
      exit(-1);
    }
    type = 1;
    dport = atoi(argv[optind + 2]);
    if (dport < 0 || dport > 65535) {
      fprintf(stderr, "Error: port (3rd option) is invalid: %s\n",
              argv[optind + 2]);
      exit(-1);
    }
  }

  if (src6 == NULL || srcmac == NULL) {
    fprintf(stderr, "Error: interface not valid: %s!\n", interface);
    exit(-1);
  }

  if (rawmode == 0 && (mac = thc_get_mac(interface, src6, dst6)) == NULL) {
    fprintf(stderr, "ERROR: Can not resolve mac address for %s\n",
            argv[optind + 1]);
    exit(-1);
  }
  strcat(string, thc_ipv62notation(src6));

  for (i = 0; i < POS_SIZE; i++) {
    position[i] = dummy;
    remark[i] = strdup("");
    rmtu[i] = 0;
  }

  if ((p = thc_pcap_init(interface, string)) == NULL) {
    fprintf(stderr, "Error: could not capture on interface %s with string %s\n",
            interface, string);
    exit(-1);
  }

  if ((mtu = thc_get_mtu(interface)) < 1280) {
    fprintf(stderr, "Error: invalid MTU (< 1280) on %s: %d\n", interface, mtu);
    exit(-1);
  }
  if ((buf = malloc(mtu + 128)) == NULL) {
    perror("malloc");
    exit(-1);
  }
  memset(buf, 0, mtu);

  if (tunnel) {
    if (type == 1) offset += 12;
    if (do_hdr_size) offset += do_hdr_size;
    orig_mtu = mtu;
    buf_len = mtu - offset;
    if (do_alert) buf_len -= 8;
  }

  if (do_alert) {
    memset(buf3, 0, sizeof(buf3));
    buf3[0] = 5;
    buf3[1] = 2;
  }

  while (thc_pcap_check(p, (char *)check_packets, NULL) > 0)
    ;
  if (type == 1) {
    baseport += getpid() % 60000;
    pid = (getpid() << 16) + getpid();
    if (tunnel == 0) buf_len = 0;
  } else {
    buf2[0] = getpid() / 256;
    buf2[1] = getpid() % 256;
    buf2[2] = buf[0];
    buf2[3] = buf[1];
    for (m = 0; m < (mtu / 4); m++)
      memcpy(buf + (m * 4), buf2, 4);
  }

  for (k = 0; k < SENDS; k++) {
    if (complete == 0) {
      for (i = 1; i <= up_to; i++) {
        if (position[i] != NULL && position[i][0] == '?') {
          if (type != 1) memset((char *)&j, i % 256, 4);
          if ((pkt =
                   thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                            src6, dst6, i, 0, 0, 0, 0)) == NULL)
            return -1;
          if (do_alert)
            if (thc_add_hdr_hopbyhop(pkt, &pkt_len, buf3, 6) < 0) return -1;
          if (type != 2) {
            if (do_frag)
              for (m = 0; m < do_frag; m++)
                if (thc_add_hdr_oneshotfragment(pkt, &pkt_len, getpid() + m) <
                    0)
                  return -1;
            if (do_dst) {
              memset(buf3, 0, 6);
              if (do_dst2) {
                buf3[0] = NXT_INVALID;
                buf3[1] = 1;
              }
              for (m = 0; m < do_dst; m++)
                if (thc_add_hdr_dst(pkt, &pkt_len, buf3, 6) < 0) return -1;
            }
          }
          if (type == 0) {
            if (thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, j,
                              (unsigned char *)buf, buf_len, 0) < 0)
              return -1;
          } else {
            if (type == 2) {
              memset(foomac, 0xff, sizeof(foomac));
              memcpy(foo6, src6, 16);
              m = 1500 - 40 - 8;
              if (foo6[8])
                foo6[8] = 0;
              else
                foo6[8] = 1;
              if ((pkt2 = thc_create_ipv6_extended(
                       interface, 0, &pkt2_len, dst6, foo6, i, 0, 0, 0, 0)) ==
                  NULL)
                return -1;
              if (thc_add_icmp6(pkt2, &pkt2_len, ICMP6_PINGREQUEST, 0, j,
                                (unsigned char *)buf, m, 0) < 0)
                return -1;
              thc_generate_pkt(interface, foomac, foomac, pkt2, &pkt2_len);
              ipv6 = (thc_ipv6_hdr *)pkt2;
              for (m = 0; m < do_toobig + do_frag; m++)
                if (thc_add_hdr_oneshotfragment(pkt, &pkt_len, getpid()) < 0)
                  return -1;
              if (do_dst) {
                memset(buf3, 0, 6);
                for (m = 0; m < do_dst; m++)
                  if (thc_add_hdr_dst(pkt, &pkt_len, buf3, 6) < 0) return -1;
              }
              if (do_hdr_size)
                m = do_hdr_size;
              else
                m = 14;
              if (do_reply) {
                if (thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREPLY, 0, 1480,
                                  (unsigned char *)ipv6->pkt + m,
                                  1280 - 40 - 8 - 8, 0) < 0)
                  return -1;
              } else if (thc_add_icmp6(pkt, &pkt_len, ICMP6_TOOBIG, 0, 1480,
                                       (unsigned char *)ipv6->pkt + m,
                                       1280 - 40 - 8 - 8, 0) < 0)
                return -1;
              pkt2 = thc_destroy_packet(pkt2);
            } else if (udp) {
              if (thc_add_udp(pkt, &pkt_len, baseport + i, dport, 0,
                              buf_len > 0 ? buf : NULL, buf_len) < 0)
                return -1;
            } else if (thc_add_tcp(pkt, &pkt_len, baseport + i, dport, pid, 0,
                                   TCP_SYN, 5760, 0, NULL, 0,
                                   buf_len > 0 ? buf : NULL, buf_len) < 0)
              return -1;
          }
          if (thc_generate_and_send_pkt(interface, srcmac, mac, pkt, &pkt_len) <
              0) {
            fprintf(stderr, "Error: Can not send packet, exiting ...\n");
            exit(-1);
          }
          pkt = thc_destroy_packet(pkt);
          usleep(1000);
        } else if (position[i] == NULL)
          up_to = i - 1;
      }
    }

    passed = time(NULL);
    while (passed + k >= time(NULL) && complete == 0)
      thc_pcap_check(p, (char *)check_packets, NULL);

    if (complete == 0 && finaldst == 0 && k + 1 < SENDS && up_to >= MAX_SEND &&
        position[up_to] != NULL /*&& position[up_to][0] != '?' */) {
      if (debug)
        printf("DEBUG: increasing range from %d to %d\n", up_to,
               up_to + INCREASE);
      up_to += INCREASE;
    }
    if (debug)
      printf("DEBUG: run %d of %d, complete %d, range %d\n", k, SENDS, complete,
             up_to);
  }

  thc_pcap_close(p);

  j = 0;
  for (i = 1; i <= up_to && position[i] != NULL; i++)
    if (position[i][0] == '?')
      j++;
    else
      j = 0;
  if (j > 0) {
    up_to -= (j - 1);
    position[up_to] = strdup("!!!");
    notreached = 1;
  }
  j = 0;
  for (i = 1; i <= up_to && position[i] != NULL; i++)
    if (position[i][0] != '?') j++;
  if (j == 0) {
    printf("Trace6 for %s unsuccessful, no packets received.\n",
           argv[optind + 1]);
  } else {
    if (tunnel) {
      snprintf(text, sizeof(text), " with starting MTU %d", orig_mtu);
      mtu = orig_mtu;
    } else
      text[0] = 0;
    printf("Trace6 for %s (%s)%s:\n", argv[optind + 1], thc_ipv62notation(dst6),
           text);
    j = 0;
    for (i = 0; i <= up_to; i++)
      if (position[i] == NULL && j == -1) j = i;
    if (j > 0) up_to = j;
    for (i = 1; i <= up_to && position[i] != NULL; i++) {
      if (tunnel && rmtu[i] > 0 && mtu > rmtu[i]) {
        if (mtu - rmtu[i] < 8)
          snprintf(text, sizeof(text), " - new MTU %d", rmtu[i]);
        else if (mtu - rmtu[i] == 20)
          snprintf(text, sizeof(text), " - new MTU %d - 6in4 tunnel endpoint",
                   rmtu[i]);
        else if (mtu - rmtu[i] == 28 || mtu - rmtu[i] == 36 ||
                 mtu - rmtu[i] == 8 || mtu - rmtu[i] == 16)
          snprintf(text, sizeof(text),
                   " - new MTU %d - PPP or Teredo tunnel endpoint", rmtu[i]);
        else if (mtu - rmtu[i] == 64)
          snprintf(text, sizeof(text), " - new MTU %d - PPTP tunnel endpoint",
                   rmtu[i]);
        else if (mtu - rmtu[i] == 80)
          snprintf(text, sizeof(text), " - new MTU %d - AYIYA tunnel endpoint",
                   rmtu[i]);
        else if (mtu - rmtu[i] > 80)
          snprintf(text, sizeof(text), " - new MTU %d", rmtu[i]);
        else
          snprintf(text, sizeof(text), " - new MTU %d", rmtu[i]);
        mtu = rmtu[i];
      } else
        text[0] = 0;
      if (resolve && position[i][0] != '?' && position[i][0] != '!') {
        // printf("foo %p\n", position[i]);
        he = gethostbyaddr(thc_resolve6(position[i]), 16, AF_INET6);
        printf(" %2d: %s (%s)%s%s\n", i, position[i],
               he != NULL ? he->h_name : "", remark[i], text);
      } else
        printf(" %2d: %s%s%s\n", i, position[i], remark[i], text);
    }
    printf("\n");
  }
  if (notreached) {
    if (do_toobig)
      printf(
          "With the -b TooBig option, the destination will not send a reply\n");
    else
      printf("The destination seems to be filtered.\n");
  }

  return 0;
}
