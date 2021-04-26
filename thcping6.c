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
#include <sys/timeb.h>
#include <ctype.h>
#include <arpa/inet.h>
#include "thc-ipv6.h"

struct timespec ts, ts2;
int             dlen = -1, port = 0, done = 0, resp_type = -1, type = NXT_ICMP6,
    fastopen = 0, client = 0, waitms = 1000000, fill = 1, notfound = 1,
    count = 1;
unsigned int sent = 0;

extern int do_pppoe;
extern int do_hdr_off;
extern int do_6in4;
extern int do_hdr_vlan;

void help(char *prg, int help) {
  printf("%s %s (c) 2020 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf(
      "Syntax: %s [-EafqxO] [-e ethertype] [-H t:l:v] [-D t:l:v] [-F dst] [-e "
      "ethertype] [-L length] [-N nextheader] [-V version] [-t ttl] [-c class] "
      "[-l label] [-d size] [-S port|-U port|-T type -C code] interface src6 "
      "dst6 [srcmac [dstmac [data]]]\n\n",
      prg);
  printf("Options:\n");
  if (help) {
    printf("  -x              flood mode (doesn't check for replies)\n");
    printf(
        "  -w ms           wait time between packets in ms (default: 1000, if "
        "-n not 1)\n");
    printf(
        "  -a              add a hop-by-hop header with router alert "
        "option.\n");
    printf(
        "  -q              add a hop-by-hop header with quickstart option.\n");
    printf("  -E              send as ethertype IPv4\n");
    printf("  -e ethertype    send as specified ethertype (hexadecimal!)\n");
    printf("  -H t:l:v        add a hop-by-hop header with special content\n");
    printf("  -D t:l:v        add a destination header with special content\n");
    printf(
        "  -D \"xxx\"        add a large destination header which fragments "
        "the packet\n");
    printf("  -f              add a one-shot fragementation header\n");
    printf("  -F ipv6address  use source routing to this final destination\n");
    printf("  -t ttl          specify TTL (default: 255)\n");
    printf("  -c class        specify a class (0-4095)\n");
    printf("  -l label        specify a label (0-1048575)\n");
    printf("  -L length       set fake payload length (0-65535)\n");
    printf("  -N nextheader   set fake next header (0-255)\n");
    printf("  -V version      set IP version (0-15)\n");
    printf("  -d data_size    define the size of the ping data buffer\n");
    printf(
        "  -O              send TCP Fast Open cookie request option (needs "
        "-S)\n");
  }
  printf("  -T number       ICMPv6 type to send (default: 128 = ping)\n");
  printf("  -C number       ICMPv6 code to send (default: 0)\n");
  printf(
      "  -S port         use a TCP SYN packet on the defined port instead of "
      "ping\n");
  printf(
      "  -U port         use a UDP packet on the defined port instead of "
      "ping\n");
  printf("  -n count        how often to send the packet (default: 1)\n");
  if (help) {
    printf("t:l:v syntax: type:length:value, value is in hex, e.g. 1:2:0eab\n");
  } else {
    printf("  -h              show more command line options (help!)\n");
  }
  printf(
      "You can put an \"x\" into src6, srcmac and dstmac for an automatic "
      "value.\n");
  printf(
      "\nCraft a ICMPv6/TCP/UDP packet with special IPv6 or EH header "
      "options.\n");
  printf(
      "Returns -1 on error or no reply, 0 on normal reply or 1 on error "
      "reply.\n");
  exit(-1);
}

void alarming() {
  if (done == 0) printf("No packet received, terminating.\n");
  exit(resp_type);
}

void check_packets(u_char *pingdata, const struct pcap_pkthdr *header,
                   const unsigned char *data) {
  int  len = header->caplen - 14, min = 0, ok = 0, nxt = 6, offset = 0, olen, i;
  long usec, fragid;
  unsigned int   mtu = 0;
  unsigned char *ptr = (unsigned char *)(data + 14), frag[64] = "";

  if (do_hdr_size) {
    ptr = (unsigned char *)(data + do_hdr_size);
    len = (header->caplen - do_hdr_size);
    if ((ptr[0] & 240) != 0x60) return;
  }

  clock_gettime(CLOCK_REALTIME, &ts2);
  if (ts2.tv_nsec < ts.tv_nsec) {
    min = 1;
    usec = (int)((1000000000 - ts.tv_nsec + ts2.tv_nsec) / 1000000);
    //    usec = (int) ((1000000000 - ts.tv_nsec + ts2.tv_nsec) / 10000);
  } else
    usec = (unsigned long int)((ts2.tv_nsec - ts.tv_nsec) / 1000000);
  //    usec = (int) ((ts2.tv_nsec - ts.tv_nsec) / 10000);
  if (ptr[nxt] == NXT_FRAG) {
    offset += 8;
    nxt = 40;
    fragid = ((unsigned char)ptr[44] << 24) + ((unsigned char)ptr[45] << 16) +
             ((unsigned char)ptr[46] << 8) + (unsigned char)ptr[47];
    sprintf(frag, " (fragmented: 0x%08lx)", fragid);
  }
  if (ptr[nxt] == NXT_ICMP6) {
    if (len < 44 + offset || ((len + 44 + offset) < dlen && dlen < 1000) ||
        (len + offset < 986 && dlen > 900)) {
      if (debug) printf("ignoring too short packet\n");
      return;
    }
    if (dlen < 1000) {
      if (memcmp(pingdata, ptr + len - dlen, dlen) == 0) ok = 1;
    } else {
      if (memcmp(pingdata, ptr + 256 + offset, 100) == 0 ||
          memcmp(pingdata, ptr + 260, 100) == 0 ||
          memcmp(pingdata, ptr + 242, 100) == 0 ||
          memcmp(pingdata, data + 260 + offset, 100) == 0)
        ok = 1;
    }
    if (ok) {
      printf("%04u.%03ld \t", (int)(ts2.tv_sec - ts.tv_sec - min), usec);
      switch (ptr[40 + offset]) {
        case ICMP6_PINGREPLY:
          if (type == NXT_ICMP6) {
            printf("pong");
            resp_type = 0;
          }
          break;
        case ICMP6_PARAMPROB:
          printf("icmp parameter problem type %d", ptr[41 + offset]);
          resp_type = 1;
          break;
        case ICMP6_REDIR:
          printf("icmp redirect");
          break;
        case ICMP6_UNREACH:
          printf("icmp unreachable type %d", ptr[41 + offset]);
          resp_type = 1;
          break;
        case ICMP6_TOOBIG:
          mtu = (ptr[44 + offset] << 24) + (ptr[45 + offset] << 16) +
                (ptr[46 + offset] << 8) + ptr[47 + offset];
          printf("icmp too big (max mtu: %d)", mtu);
          resp_type = 1;
          break;
        case ICMP6_TTLEXEED:
          printf("icmp ttl exceeded");
          resp_type = 1;
          break;
        case ICMP6_PINGREQUEST:
          printf("own ping seen (ignore this)\n");
          resp_type = -1;
          break;
        default:
          // ignored
          printf("icmp6 %d:%d", ptr[40 + offset], ptr[41 + offset]);
          resp_type = 0;
      }
      if (fill) printf(" for seq=%u", sent);
      printf("\n");
    } else
      printf(
          "(ignoring icmp6 packet with different contents (proto %d, type %d, "
          "code %d)) ",
          ptr[nxt], ptr[40 + offset], ptr[41 + offset]);
  } else {
    if (type == NXT_TCP && ptr[nxt] == NXT_TCP) {
      printf("%04u.%03ld \ttcp-", (int)(ts2.tv_sec - ts.tv_sec - min), usec);
      switch ((ptr[53 + offset] % 8)) {
        case 2:
          if (ptr[53 + offset] >= TCP_ACK) {
            printf("syn-ack");
            resp_type = 0;
          } else {
            printf("syn (double?)");
            resp_type = 1;
          }
          break;
        case 4:
          printf("rst");
          resp_type = 1;
          break;
        default:
          printf("illegal");
          resp_type = 1;
          break;
      }
      if (fill) printf(" for seq=%u", sent);
      if (fastopen && len > 62 + offset) {
        if (ptr[60 + offset] == 23) {
          olen = ptr[61 + offset];
          if (len < olen + 62 + offset) olen = len - 62 - offset;
          printf(" TCP Fast Open cookie: ");
          for (i = 0; i < olen; i++)
            printf("%02x", (unsigned char)ptr[62 + offset + i]);
        } else
          printf(" (no fast open reply)");
      }
    } else if (type == NXT_UDP && ptr[nxt] == NXT_UDP)
      printf("%04u.%03ld \tudp", (int)(ts2.tv_sec - ts.tv_sec - min), usec);
  }
  if (resp_type >= 0)
    printf(" packet received from %s%s\n", thc_ipv62notation(ptr + 8), frag);
  if (done == 0 && resp_type >= 0) {
    done = 1;
    if (count == 1) {
      alarm(1);
      notfound = 0;
    }
  }
}

int main(int argc, char *argv[]) {
  unsigned char *pkt1 = NULL, buf[2096] = "thcping6", *routers[2],
                buf2[1300] = "";
  unsigned char *src6 = NULL, *dst6 = NULL, smac[16] = "", dmac[16] = "",
                *srcmac = smac, *dstmac = dmac;
  char string[256] = "ip6 and dst ", *interface, *d_opt = NULL, *h_opt = NULL,
       *oo, *ol, *ov;
  int pkt1_len = 0, flags = 0, frag = 0, alert = 0, quick = 0, route = 0,
      ttl = 255, label = 0, class = 0, i, j, k, ether = -1, xl = 0,
      frag_type = NXT_ICMP6, offset = 14, icmptype = ICMP6_PINGREQUEST,
      icmpcode = 0, flood = 0, fake_len = -1, fake_ver = 0, fake_nxt = -1,
      olen = 0;
  pcap_t *      p = NULL;
  thc_ipv6_hdr *hdr;

  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  if (argc > 1 && strncmp(argv[1], "-h", 2) == 0) help(argv[0], 1);
  if (argc < 3) help(argv[0], 0);

  memset(buf, 0, sizeof(buf));
  while ((i = getopt(argc, argv,
                     "w:aqfd:D:H:xF:t:c:l:OS:U:EXn:T:C:e:L:N:V:")) >= 0) {
    switch (i) {
      case 'e':
        if (strncmp(optarg, "0x", 2) == 0)
          sscanf(optarg + 2, "%x", (int *)&ether);
        else
          sscanf(optarg, "%x", (int *)&ether);
        break;
      case 'w':
        waitms = atoi(optarg) * 1000;
        break;
      case 'O':
        fastopen = 1;
        break;
      case 'L':
        fake_len = atoi(optarg);
        break;
      case 'N':
        fake_nxt = atoi(optarg);
        break;
      case 'V':
        fake_ver = atoi(optarg);
        break;
      case 'T':
        icmptype = atoi(optarg);
        break;
      case 'C':
        icmpcode = atoi(optarg);
        break;
      case 'X':
        debug = 1;
        break;
      case 'x':
        flood = 1;
        break;
      case 'a':
        alert = 1;
        break;
      case 'q':
        quick = 1;
        break;
      case 'f':
        frag++;
        break;
      case 'E':
        ether = 0x0800;
        break;
      case 'F':
        route = 1;
        if ((routers[0] = thc_resolve6(optarg)) == NULL) {
          fprintf(stderr,
                  "Error: %s does not resolve to a valid IPv6 address\n",
                  optarg);
          exit(-1);
        }
        routers[1] = NULL;
        break;
      case 'S':
        port = atoi(optarg);
        type = NXT_TCP;
        break;
      case 'U':
        port = atoi(optarg);
        type = NXT_UDP;
        break;
      case 'D':
        d_opt = optarg;
        break;
      case 'H':
        h_opt = optarg;
        break;
      case 't':
        ttl = atoi(optarg);
        break;
      case 'c':
        class = atoi(optarg);
        break;
      case 'l':
        label = atoi(optarg);
        break;
      case 'n':
        count = atoi(optarg);
        if (count == 0) count = -1;
        break;
      case 'd':
        dlen = atoi(optarg);
        fill = 0;
        if (dlen > 2096) dlen = 2096;
        for (j = 0; j < (dlen / 8); j++)
          memcpy(buf + j * 8, "thcping6", 8);
        break;
      default:
        fprintf(stderr, "Error: invalid option %c\n", i);
        exit(-1);
    }
  }

  if (argc - optind < 2) help(argv[0], 0);

  if (dlen == -1) {
    if (type == NXT_TCP)
      dlen = 0;
    else {
      dlen = 8;
      memset(buf, 0, sizeof(buf));
    }
  }

  if (port < 1024 && (type == NXT_TCP || type == NXT_UDP)) client = 1024;

  if (fastopen && type != NXT_TCP) {
    fprintf(stderr,
            "Error: TCP Fast Open option (-O) requires sendig TCP SYN packets "
            "(-S)\n");
    exit(-1);
  }

  if (do_hdr_size) offset = do_hdr_size;
  interface = argv[optind];
  if (argc - optind == 2) {
    dst6 = thc_resolve6(argv[optind + 1]);
    if ((src6 = thc_get_own_ipv6(interface, dst6, PREFER_GLOBAL)) == NULL) {
      fprintf(stderr, "Error: no IPv6 address found for interface %s!\n",
              interface);
      exit(-1);
    }
  } else {
    dst6 = thc_resolve6(argv[optind + 2]);
    if (strcmp(argv[optind + 1], "x") != 0)
      src6 = thc_resolve6(argv[optind + 1]);
    else if ((src6 = thc_get_own_ipv6(interface, dst6, PREFER_GLOBAL)) ==
             NULL) {
      fprintf(stderr, "Error: no IPv6 address found for interface %s!\n",
              interface);
      exit(-1);
    }
  }
  if (thc_get_own_ipv6(interface, NULL, PREFER_GLOBAL) == NULL) {
    fprintf(stderr, "Error: invalid interface %s\n", interface);
    exit(-1);
  }

  strcat(string, thc_ipv62notation(src6));

  if (argc - optind >= 4) {
    if (strcmp(argv[optind + 3], "x") != 0)
      sscanf(argv[optind + 3], "%x:%x:%x:%x:%x:%x", (unsigned int *)&smac[0],
             (unsigned int *)&smac[1], (unsigned int *)&smac[2],
             (unsigned int *)&smac[3], (unsigned int *)&smac[4],
             (unsigned int *)&smac[5]);
    else
      srcmac = NULL;
  } else
    srcmac = NULL;
  if (argc - optind >= 5) {
    if (strcmp(argv[optind + 4], "x") != 0)
      sscanf(argv[optind + 4], "%x:%x:%x:%x:%x:%x", (unsigned int *)&dmac[0],
             (unsigned int *)&dmac[1], (unsigned int *)&dmac[2],
             (unsigned int *)&dmac[3], (unsigned int *)&dmac[4],
             (unsigned int *)&dmac[5]);
    else
      dstmac = NULL;
  } else
    dstmac = NULL;

  do {
    sent++;
    done = 0;
    if ((pkt1 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt1_len,
                                         src6, dst6, ttl, 0, label, class,
                                         fake_ver)) == NULL)
      return -1;
    if (alert || quick) {
      j = 0;
      memset(buf2, 0, sizeof(buf2));
      if (alert) {
        buf2[0] = 5;
        buf2[1] = 2;
        j = 4;
      }
      if (quick) {
        buf2[j] = 38;
        buf2[j + 1] = 6;
        buf2[j + 3] = 255;
        j += 8;
      }
      while ((j + 2) % 8 != 0)
        j++;
      if (thc_add_hdr_hopbyhop(pkt1, &pkt1_len, buf2, j) < 0) return -1;
      frag_type = NXT_HBH;
    }
    if (h_opt != NULL) {
      memset(buf2, 0, sizeof(buf2));
      frag_type = NXT_HBH;
      oo = h_opt;
      if ((ol = index(oo, ':')) == NULL) {
        fprintf(stderr,
                "Error: option value  must be optionnumber:length:value, e.g. "
                "1:2:feab -> %s\n",
                h_opt);
        exit(-1);
      }
      *ol++ = 0;
      if ((ov = index(ol, ':')) == NULL) {
        fprintf(stderr,
                "Error: option value must be optionnumber:length:value, e.g. "
                "1:2:feab -> %s\n",
                h_opt);
        exit(-1);
      }
      *ov++ = 0;
      buf2[0] = (atoi(oo)) % 256;
      buf2[1] = (atoi(ol)) % 256;
      if (*ov != 0)
        for (i = 0; i < strlen(ov) / 2; i++) {
          if (tolower(ov[i * 2]) >= 'a' && tolower(ov[i * 2]) <= 'f')
            j = (ov[i * 2] - 'a' + 10) * 16;
          else if (ov[i * 2] >= '0' && ov[i * 2] <= '9')
            j = (ov[i * 2] - '0') * 16;
          else {
            fprintf(
                stderr,
                "Error: only hexadecimal characters are allowed in value: %s\n",
                ov);
            exit(-1);
          }
          if (tolower(ov[i * 2 + 1]) >= 'a' && tolower(ov[i * 2 + 1]) <= 'f')
            j += (ov[i * 2 + 1] - 'a' + 10);
          else if (ov[i * 2 + 1] >= '0' && ov[i * 2 + 1] <= '9')
            j += (ov[i * 2 + 1] - '0');
          else {
            fprintf(
                stderr,
                "Error: only hexadecimal characters are allowed in value: %s\n",
                ov);
            exit(-1);
          }
          buf2[2 + i] = j % 256;
        }
      if (thc_add_hdr_hopbyhop(pkt1, &pkt1_len, buf2, 2 + (atoi(ol) % 256)) < 0)
        return -1;
    }
    if (frag) {
      for (k = 0; k < frag; k++)
        if (thc_add_hdr_oneshotfragment(pkt1, &pkt1_len, getpid() + k + flood) <
            0)
          return -1;
      if (frag_type == NXT_DST) frag_type = NXT_FRAG;
    }
    if (route) {
      if (thc_add_hdr_route(pkt1, &pkt1_len, routers, 1) < 0) return -1;
      if (frag_type == NXT_DST) frag_type = NXT_ROUTE;
    }
    if (d_opt != NULL) {
      memset(buf2, 0, sizeof(buf2));
      if (d_opt[0] == 'x') {
        xl = 1;
        frag_type = NXT_DST;
        if (thc_add_hdr_dst(pkt1, &pkt1_len, buf2, sizeof(buf2)) < 0) return -1;
      } else {
        oo = d_opt;
        if ((ol = index(oo, ':')) == NULL) {
          fprintf(stderr,
                  "Error: option value must be optionnumber:length:value, e.g. "
                  "1:2:feab: %s\n",
                  h_opt);
          exit(-1);
        }
        *ol++ = 0;
        if ((ov = index(ol, ':')) == NULL) {
          fprintf(stderr,
                  "Error: option value must be optionnumber:length:value, e.g. "
                  "1:2:feab: %s\n",
                  h_opt);
          exit(-1);
        }
        *ov++ = 0;
        buf2[0] = (atoi(oo)) % 256;
        buf2[1] = (atoi(ol)) % 256;
        if (*ov != 0)
          for (i = 0; i < strlen(ov) / 2; i++) {
            if (tolower(ov[i * 2]) >= 'a' && tolower(ov[i * 2]) <= 'f')
              j = (ov[i * 2] - 'a' + 10) * 16;
            else if (ov[i * 2] >= '0' && ov[i * 2] <= '9')
              j = (ov[i * 2] - '0') * 16;
            else {
              fprintf(stderr,
                      "Error: only hexadecimal characters are allowed in "
                      "value: %s\n",
                      ov);
              exit(-1);
            }
            if (tolower(ov[i * 2 + 1]) >= 'a' && tolower(ov[i * 2 + 1]) <= 'f')
              j += (ov[i * 2 + 1] - 'a' + 10);
            else if (ov[i * 2 + 1] >= '0' && ov[i * 2 + 1] <= '9')
              j += (ov[i * 2 + 1] - '0');
            else {
              fprintf(stderr,
                      "Error: only hexadecimal characters are allowed in "
                      "value: %s\n",
                      ov);
              exit(-1);
            }
            buf2[2 + i] = j % 256;
          }
        if (thc_add_hdr_dst(pkt1, &pkt1_len, buf2, 2 + (atoi(ol) % 256)) < 0)
          return -1;
      }
    }
    if (argc - optind >= 6) {
      if (dlen != 8) {
        fprintf(stderr,
                "Warning: the data option is ignored if the -d option is "
                "supplied\n");
      } else {
        dlen = strlen(argv[optind + 5]);
        if (dlen > sizeof(buf)) dlen = sizeof(buf) - 1;
        memcpy(buf, argv[optind + 5], dlen);
        buf[dlen] = 0;
        fill = 0;
      }
    }
    if ((port == 0 || type == NXT_UDP) && fill)
      memcpy(buf, (char *)&sent, sizeof(sent));
    if (port == 0) {
      if (thc_add_icmp6(pkt1, &pkt1_len, icmptype, icmpcode, flags,
                        (unsigned char *)&buf, dlen, 0) < 0)
        return -1;
    } else if (type == NXT_TCP) {
      memset(buf2, 0, sizeof(buf2));
      if (fastopen) {
        memset(buf2, 0, sizeof(buf2));
        olen = 4;
        buf2[0] = 34;
        buf2[1] = 2;
      }
      if (thc_add_tcp(pkt1, &pkt1_len, port + flood + client, port, sent, 0,
                      TCP_SYN, 5760, 0, (unsigned char *)&buf2, olen,
                      (unsigned char *)&buf, dlen) < 0)
        return -1;
    } else if (thc_add_udp(pkt1, &pkt1_len, port + flood + client, port, 0,
                           (unsigned char *)&buf, dlen) < 0)
      return -1;

    if (thc_generate_pkt(interface, srcmac, dstmac, pkt1, &pkt1_len) < 0) {
      fprintf(stderr, "Error: Can not generate packet, exiting ...\n");
      exit(-1);
    }

    hdr = (thc_ipv6_hdr *)pkt1;

    if (fake_nxt != -1) {
      if (do_hdr_size) {
        hdr->pkt[6 + do_hdr_size] =
            (unsigned char)((unsigned int)fake_nxt % 256);
      } else
        hdr->pkt[20] = (unsigned char)((unsigned int)fake_nxt % 256);
    }

    if (fake_len != -1) {
      if (do_hdr_size) {
        hdr->pkt[4 + do_hdr_size] =
            (unsigned char)(((unsigned int)fake_len % 65536) / 256);
        hdr->pkt[5 + do_hdr_size] =
            (unsigned char)((unsigned int)fake_len % 256);
      } else {
        hdr->pkt[18] =
            (unsigned char)(((unsigned int)fake_len % 65536) /
                            256);  // ethernet protocol value for IPv4
        hdr->pkt[19] = (unsigned char)((unsigned int)fake_len % 256);
      }
    }

    if (ether != -1) {
      if (do_hdr_size) {
        if (do_pppoe) {
          hdr->pkt[20 + do_hdr_off] = 0;  // PPP protocol value for IPv4
          hdr->pkt[21 + do_hdr_off] = 0x21;
        } else if (do_hdr_vlan && do_6in4 == 0) {
          hdr->pkt[16] = 8;  // ethernet protocol value for IPv4
          hdr->pkt[17] = 0;
        } else
          fprintf(stderr,
                  "Warning: ether option does not work with 6in4 injection\n");
      } else {
        hdr->pkt[12] =
            (unsigned char)(((unsigned int)ether % 65536) /
                            256);  // ethernet protocol value for IPv4
        hdr->pkt[13] = (unsigned char)((unsigned int)ether % 256);
      }
    }

    signal(SIGALRM, alarming);

    if (p == NULL)
      if ((p = thc_pcap_init(interface, string)) == NULL) {
        fprintf(stderr,
                "Error: could not capture on interface %s with string %s\n",
                interface, string);
        exit(-1);
      }

    if (xl || hdr->pkt_len > thc_get_mtu(interface))
      // for (i = 0; i < count; i++)
      thc_send_as_fragment6(interface, src6, dst6, frag_type,
                            hdr->pkt + 40 + offset, hdr->pkt_len - 40 - offset,
                            1280);
    else
      // for (i = 0; i < count; i++)
      while (thc_send_pkt(interface, pkt1, &pkt1_len) < 0)
        usleep(1);
    clock_gettime(CLOCK_REALTIME, &ts);
    if (flood < 2) {
      printf("0000.000 \t%s packet sent to %s\n",
             port == 0 ? "ping" : type == NXT_TCP ? "tcp-syn" : "udp",
             thc_ipv62notation(dst6));
      if (flood == 1 && type != NXT_TCP && type != NXT_UDP && frag == 0) {
        if (xl)
          for (i = 0; i < count; i++)
            thc_send_as_fragment6(interface, src6, dst6, frag_type,
                                  hdr->pkt + 40 + offset,
                                  hdr->pkt_len - 40 - offset, 1280);
        else
          for (i = 0; i < count; i++)
            while (thc_send_pkt(interface, pkt1, &pkt1_len) < 0)
              usleep(1);
      }
    }
    {
      int slices = waitms / 500, counter;
      for (counter = 0; counter < slices /*&& done == 0*/; counter++) {
        usleep(500);
        while (thc_pcap_check(p, (char *)check_packets, buf) > 0)
          ;
      }
    }
    pkt1 = thc_destroy_packet(pkt1);
    if (flood > 0) flood++;
    if (count > 0) count--;
  } while (flood != 0 || count != 0);
  alarm(2);
  while (notfound) {
    thc_pcap_check(p, (char *)check_packets, buf);
  }

  return resp_type;  // not reached
}
