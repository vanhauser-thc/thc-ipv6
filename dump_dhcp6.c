#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <ctype.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <sys/select.h>
#include "thc-ipv6.h"

char *interface = NULL, *dns_name = NULL, elapsed[6] = {0, 8, 0, 2, 0, 0};
int   counter = 0;

// start0: 1-3 rand, 18-21 rand, 22-27 mac, 32-35 rand
char solicit[] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00,
                  0x00, 0x01, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
                  0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x10, 0x00, 0x15,
                  0x00, 0x17, 0x00, 0x1f, 0x00, 0x38, 0x00, 0x40, 0x00, 0x63,
                  0x00, 0x7b, 0x00, 0xc7, 0x00, 0x14, 0x00, 0x00, 0x00, 0x19,
                  0x00, 0x29, 0x00, 0x00, 0x00, 0x01,  // prefix deleg req
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1a,
                  0x00, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

char inforeq[] = {0x0b, 0x3a, 0x48, 0x79, 0x00, 0x08, 0x00, 0x02, 0x06, 0x40,
                  0x00, 0x01, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x1a, 0x7d,
                  0x43, 0x48, 0x3c, 0x97, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x10,
                  0x00, 0x0e, 0x00, 0x00, 0x01, 0x37, 0x00, 0x08, 0x4d, 0x53,
                  0x46, 0x54, 0x20, 0x35, 0x2e, 0x30, 0x00, 0x06, 0x00, 0x08,
                  0x00, 0x18, 0x00, 0x17, 0x00, 0x11, 0x00, 0x20};
char dnsupdate1[] = {0, 39, 0, 8, 1, 6, 122, 97, 97, 97, 97, 97};
char dnsupdate2[] = {0, 6, 0, 2, 0, 39};

void help(char *prg) {
  printf("%s %s (c) 2020 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf("Syntax: %s [-V vendorid] interface [target]\n\n", prg);
  printf("Options:\n");
  printf("  -V vendorid  send vendorid number,string (e.g. 11,test)\n");
  printf("  -N           use fe80:: as source\n");
  printf("  -n           use empty mac as source\n");
  printf(
      "\nDHCPv6 information tool. Dumps the available servers and their "
      "setup.\n");
  printf("You can specify a specific DHCPv6 server as destination.\n");
  exit(-1);
}

void clean_exit(int signo) {
  printf("\n%d replies received\n", counter);
  exit(0);
}

void check_packets(u_char *foo, const struct pcap_pkthdr *header,
                   const unsigned char *data) {
  int            len = header->caplen, rlen, i, j, k;
  unsigned char *ptr = (unsigned char *)data, *rdata, type;
  char           mybuf[1024] = {0x03, 0, 0, 0, 0, 8, 0, 2, 0, 0};

  if (do_hdr_size) {
    data += do_hdr_size;
    len -= do_hdr_size;
    if ((data[0] & 240) != 0x60) return;
  } else {
    data += 14;
    len -= 14;
  }
  rlen = len;
  rdata = (unsigned char *)data;

  // printf("x %d < 126, %d != %d, %d != 2||7\n", len, data[6], NXT_UDP,
  // data[48]);
  if (len < 100 || data[6] != NXT_UDP || (data[48] != 2 && data[48] != 7))
    return;
  // printf("y\n");

  type = data[48];
  data += 48;
  len -= 48;

  memcpy(mybuf + 1, data + 1, 3);
  data += 4;
  len -= 4;

  /*
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
          if (olen == 14)
            smac = (char *) (data + 12);
          else
            smac = mac;
        }
        data += olen + 4;
        len -= olen + 4;
        if (len < 0) {
          printf("Information: evil packet received\n");
          len = -1;
        }
      }
    }
  */
  if (len >= 4) {
    counter++;
    printf("\nDHCPv6 packet received: %s\n", type == 2 ? "Advertise" : "Reply");
    printf("  Server IP6: %s\n", thc_ipv62notation(rdata + 8));
    printf("  Server MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", ptr[6], ptr[7],
           ptr[8], ptr[9], ptr[10], ptr[11]);
    while (len >= 4) {
      i = data[0] * 256 + data[1];
      j = data[2] * 256 + data[3];
      if (j + 4 > len) {
        printf("Evil Packet!\n");
        return;
      }
      switch (i) {
        case 1:
          // printf(""); // client identifier
          break;
        case 2:
          if (j > 0) {
            printf("    Server Identifier: ");  // server identifier
            for (k = 0; k < j; k++) {
              printf("%02x", (unsigned char)data[4 + k]);
            }
            printf("\n");
          }
          break;
        case 3:
          if (j >= 16 && data[16] == 0 && data[17] == 5)
            printf("    Address Offered: %s\n",
                   thc_ipv62notation((unsigned char *)data + 20));
          break;
        case 7:
          printf("    Preferred value (not implemented)\n");  // preferred value
          break;
        case 13:
        case 19:
          if (j >= 2) {
            printf("    Status Code: %d", data[4] * 256 + data[5]);
            if (j > 2) {
              printf(" (");
              for (k = 0; k < (j - 2); k++)
                printf("%c", isprint(data[6 + k]) ? data[6 + k] : '.');
              printf(")");
            }
            printf("\n");
          }
          break;
        case 20:
          printf("    Reconfigure Request: Accepted\n");  // reconfigure accept
          break;
        case 21:
          printf("    SIP Domain List: ");  // sip server domain list
          for (k = 1; k < j; k++) {
            if (data[4 + k] == 0 && k + 1 < j) {
              printf(". + ");
              k++;
            } else
              printf("%c", isprint(data[4 + k]) ? data[4 + k] : '.');
          }
          printf("\n");
          break;
        case 23:
          if (j >= 16)
            for (k = 0; k < (j / 16); k++)
              printf("    DNS Server: %s\n",
                     thc_ipv62notation((unsigned char *)data + 4 + (k * 16)));
          break;
        case 25:
          if (data[17] == 0x1a)
            printf("    Prefix Delegation: %s\n",
                   thc_ipv62notation((unsigned char *)data + 29));
          break;
        case 31:
          if (j >= 16)
            for (k = 0; k < (j / 16); k++)
              printf("    NTP Server: %s\n",
                     thc_ipv62notation((unsigned char *)data + 4 + (k * 16)));
          break;
        case 32:
          if (j >= 4)
            printf("    Lifetime: %u\n",
                   (unsigned int)((data[4] << 24) + (data[5] << 16) +
                                  (data[6] << 8) + data[7]));
          break;
        case 64:
          if (j > 1) {
            printf("    AFTR Server: ");
            for (k = 0; k < (j - 1); k++)
              printf("%c", isprint(data[5 + k]) ? data[5 + k] : '.');
            printf("\n");
          }
          break;
        case 99:
          if (j >= 16)
            for (k = 0; k < (j / 16); k++)
              printf("    DHCPv4OverIPv6 Server: %s\n",
                     thc_ipv62notation((unsigned char *)data + 4 + (k * 16)));
          break;
        case 199:
          if (j >= 16)
            for (k = 0; k < (j / 16); k++)
              printf("    ?199? Server: %s\n",
                     thc_ipv62notation((unsigned char *)data + 4 + (k * 16)));
          break;
        default:
          printf("    Unknown option type: %d\n", i);
      }
      len -= (4 + j);
      data += (4 + j);
    }
    printf("\n");
  }
}

int main(int argc, char *argv[]) {
  char           mac[6] = {0, 0x0c, 0, 0, 0, 0}, *pkt = NULL, *pkt2 = NULL;
  char           wdatabuf[1024], wdatabuf2[1024];
  unsigned char *mac6 = mac, *src, *dst, *vendorid = NULL, *ptr;
  int i, s, len, len2, pkt_len = 0, pkt2_len = 0, source = PREFER_LINK,
                       hlim = 1;
  unsigned long long int count = 0;
  pcap_t *               p = NULL;
  int                    do_all = 1, use_real_mac = 1, use_real_link = 1;

  if (argc < 2 || strncmp(argv[1], "-h", 2) == 0) help(argv[0]);

  if (getenv("THC_IPV6_PPPOE") != NULL || getenv("THC_IPV6_6IN4") != NULL)
    printf("WARNING: %s is not working with injection!\n", argv[0]);

  while ((i = getopt(argc, argv, "V:dnNr1")) >= 0) {
    switch (i) {
      case 'N':
        use_real_link = 0;  // no break
      case 'n':
        use_real_mac = 0;
        break;
      case '1':
        do_all = 0;
        break;
      case 'V':
        vendorid = optarg;
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
  if (thc_get_own_ipv6(interface, NULL, PREFER_LINK) == NULL) {
    fprintf(stderr, "Error: invalid interface %s\n", interface);
    exit(-1);
  }
  if (argv[optind + 1] != NULL && strlen(argv[optind + 1]) > 0) {
    dst = thc_resolve6(argv[optind + 1]);
    if (dst[0] != 0 && dst[0] != 0xff && dst[0] != 0xfe) {
      source = PREFER_GLOBAL;
      hlim = 64;
    }
    dns_name = argv[optind + 2];  // can be NULL but this is not used yet
  } else {
    dst = thc_resolve6("ff02::1:2");
    dns_name = NULL;
  }
  if (use_real_link)
    src = thc_get_own_ipv6(interface, NULL, source);
  else
    src = thc_resolve6("fe80::");
  if (use_real_mac) mac6 = thc_get_own_mac(interface);
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

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
  len2 = sizeof(inforeq);
  memcpy(wdatabuf2, inforeq, len2);

  printf("Sending DHCPv6 Solicitate message ...\n");
  printf("Sending DHCPv6 Information Request message ...\n");
  if (!use_real_link) memcpy(src + 8, (char *)&count, 8);
  // start0: 1-3 rand, 18-21 rand, 22-27 mac, 32-35 rand
  for (i = 0; i < 3; i++) {
    wdatabuf[i + 32] = rand() % 256;
    wdatabuf[i + 18] = rand() % 256;
    mac[i + 2] = rand() % 256;
  }
  if (!use_real_mac) memcpy(wdatabuf + 22, mac, 6);
  if (!use_real_mac) memcpy(wdatabuf2 + 18, mac, 6);
  memcpy(wdatabuf + 1, (char *)&count + _TAKE3, 3);
  memcpy(wdatabuf2 + 1, (char *)&count + _TAKE3, 3);

  if (vendorid != NULL) {
    if ((ptr = index(vendorid, ',')) == NULL) {
      fprintf(stderr, "Error: invalid vendorid syntax: %s\n", vendorid);
      exit(-1);
    }
    *ptr++ = 0;
    i = atoi(vendorid);
    wdatabuf[len] = 0;
    wdatabuf[len + 1] = 0x10;
    wdatabuf[len + 2] = (4 + 2 + strlen(ptr)) / 256;
    wdatabuf[len + 3] = (4 + 2 + strlen(ptr)) % 256;
    wdatabuf[len + 4] = ((i & 0xff000000) >> 24);
    wdatabuf[len + 5] = ((i & 0x00ff0000) >> 16);
    wdatabuf[len + 6] = ((i & 0x0000ff00) >> 8);
    wdatabuf[len + 7] = i % 256;
    wdatabuf[len + 8] = strlen(ptr) / 256;
    wdatabuf[len + 9] = strlen(ptr) % 256;
    memcpy(wdatabuf + len + 10, ptr, strlen(ptr));
    memcpy(wdatabuf2 + len2, wdatabuf + len, 10 + strlen(ptr));
    len += 10 + strlen(ptr);
    len2 += 10 + strlen(ptr);
  }

  if ((pkt = thc_create_ipv6_extended(interface, source, &pkt_len, src, dst,
                                      hlim, 0, 0, 0, 0)) == NULL)
    return -1;
  if (thc_add_udp(pkt, &pkt_len, 546, 547, 0, wdatabuf, len) < 0) return -1;
  if (thc_generate_and_send_pkt(interface, mac6, NULL, pkt, &pkt_len) < 0)
    printf("!");
  if ((pkt2 = thc_create_ipv6_extended(interface, source, &pkt2_len, src, dst,
                                       hlim, 0, 0, 0, 0)) == NULL)
    return -1;
  if (thc_add_udp(pkt2, &pkt2_len, 546, 547, 0, wdatabuf2, len2) < 0) return -1;
  if (thc_generate_and_send_pkt(interface, mac6, NULL, pkt2, &pkt2_len) < 0)
    printf("!");
  signal(SIGALRM, clean_exit);
  alarm(2);
  //  i = thc_send_pkt(interface, pkt, &pkt_len);
  pkt = thc_destroy_packet(pkt);
  while (1) {
    usleep(75);
    while (thc_pcap_check(p, (char *)check_packets, NULL) > 0)
      ;
  }

  return 0;  // never reached
}
