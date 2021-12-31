#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <pcap.h>
#include "thc-ipv6.h"

extern int   thc_socket;
extern char *do_hdr;
extern int   do_hdr_off;

int   type = 0, passive = 0, active = 0;
char *interface;

void help(char *prg) {
  printf("%s %s (c) 2022 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf("Syntax: %s [-ap] interface\n\n", prg);
  printf(
      "This tool answers to keep-alive requests on PPPoE and 6in4 tunnels; for "
      "PPPoE\nit also sends keep-alive requests.\n");
  printf(
      "Note that the appropriate environment variable THC_IPV6_{PPPOE|6IN4} "
      "must be set\n");
  printf("Option -a will actively send alive requests every 15 seconds.\n");
  printf("Option -p will not send replies to alive requests.\n");
  exit(-1);
}

void intercept(u_char *foo, const struct pcap_pkthdr *header,
               const unsigned char *data) {
  unsigned char *     ipv6hdr, *pkt, buf[1500];
  int                 len = header->caplen, pkt_len = 0;
  unsigned int *      seq, offset = 0;
  unsigned short int *orig, *seen;
  thc_ipv6_hdr        hdr;

  if (debug) {
    printf("DEBUG: packet received\n");
    thc_dump_data((unsigned char *)data, len, "Received packet on tunnel");
  }

  if (type == 2) {  // 6in4
    len -= do_hdr_size;
    ipv6hdr = (unsigned char *)(data + do_hdr_size);
    if ((ipv6hdr[0] & 240) != 0x60) return;
    if (len < 48 || ipv6hdr[6] != NXT_ICMP6 || ipv6hdr[41] != 0) return;
    seq = (unsigned int *)(ipv6hdr + 44);
    if (ipv6hdr[40] == ICMP6_PINGREQUEST) {
      printf("Keep-alive ping request ID 0x%x seen\n", htonl(*seq));
      if (passive == 0) {
        if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                            ipv6hdr + 24, ipv6hdr + 8, 255, 0,
                                            0, 0, 0)) == NULL)
          return;
        if (thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREPLY, 0, htonl(*seq),
                          (unsigned char *)ipv6hdr + 40 + 8, len - 40 - 8,
                          0) < 0)
          return;
        if (thc_generate_and_send_pkt(interface, NULL, NULL, pkt, &pkt_len) < 0)
          return;
        pkt = thc_destroy_packet(pkt);
        printf("Keep-alive ping reply ID 0x%x sent\n", htonl(*seq));
      }
    }
    if (passive && ipv6hdr[40] == ICMP6_PINGREPLY)
      printf("Keep-alive ping reply ID 0x%x seen\n", htonl(*seq));
  } else {  // PPPoE
    seen = (unsigned short int *)(data + 20 + offset + do_hdr_off);
    if (len < 40 || len > 1500 || htons(*seen) != 0xc021) return;
    seen = (unsigned short int *)(data + 16 + offset + do_hdr_off);
    if (memcmp(data + 16 + offset + do_hdr_off,
               do_hdr + 16 + offset + do_hdr_off, 2) != 0) {
      orig = (unsigned short int *)(do_hdr + 16 + offset + do_hdr_off);
      fprintf(stderr,
              "Warning: PPPoE SessionID is different to that defined in the "
              "environment variable! ((specified) %04x != %04x (seen))\n",
              htons(*orig), htons(*seen));
    }
    if (data[22 + offset + do_hdr_off] == 9) {
      printf("Keep-alive request ID 0x%04x seen\n", htons(*seen));
      if (passive == 0) {
        memcpy(buf + 12, data + 12, len - 12);
        memcpy(buf + 6, data, 6);
        memcpy(buf, data + 6, 6);
        buf[22 + offset + do_hdr_off] = 10;
        hdr.pkt = buf;
        hdr.pkt_len = len;
        if (thc_send_pkt(interface, (unsigned char *)&hdr, &len) < 0) {
          fprintf(stderr, "Error: could not send packet to interface %s (%d)\n",
                  interface, thc_socket);
          exit(-1);
        }
        printf("Keep-alive reply ID 0x%04x sent\n", htons(*seen));
      }
    } else {
      if (passive && data[22 + offset + do_hdr_off] == 10)
        printf("Keep-alive reply ID 0x%04x seen\n", htons(*seen));
    }
  }

  return;
}

int main(int argc, char *argv[]) {
  char         sndbuf[128], data[] = {0x09, 0x0a, 0x00, 0x0c, 0xfa, 0xce,
                              0xba, 0xbe, 0x1f, 0x1e, 0x1d, 0x1c};
  time_t       passed = 0;
  pcap_t *     p;
  thc_ipv6_hdr hdr;
  int          sndbuflen = 0, i;

  if (argc < 2 || strncmp(argv[1], "-h", 2) == 0) help(argv[0]);

  while ((i = getopt(argc, argv, "adp")) >= 0) {
    switch (i) {
      case 'a':
        active = 1;
        break;
      case 'd':
        debug = 1;
        break;
      case 'p':
        passive = 1;
        break;
      default:
        fprintf(stderr, "Error: invalid option -%c\n", i);
        exit(-1);
    }
  }

  if (getenv("THC_IPV6_PPPOE") != NULL)
    type = 1;
  else if (getenv("THC_IPV6_6IN4") != NULL)
    type = 2;

  if (type == 0) {
    fprintf(stderr,
            "Error: neither the THC_IPV6_PPPOE nor THC_IPV6_6IN4 environment "
            "variable is set\n");
    exit(-1);
  }

  if (type == 2 && active)
    fprintf(stderr,
            "Error: active ping6 sending in for THC_IPV6_6IN4 is not possible. "
            "Please use thcping6 or alive6 to perform the active alive packet "
            "sending.\n");

  interface = argv[optind];

  if (thc_get_own_mac(interface) == NULL) {
    fprintf(stderr, "Error: invalid interface %s\n", interface);
    exit(-1);
  }

  printf("Started %s keep-alive watcher on %s (Press Control-C to end) ...\n",
         type == 1 ? "PPPoE" : "6in4", argv[optind]);
  if (active == 1 && type == 1) {
    if ((p = thc_pcap_init_promisc(
             interface, "it does not matter what we put here")) == NULL) {
      fprintf(stderr, "Error: Could not set interface into promiscious mode\n");
      exit(-1);
    }
    memcpy(sndbuf, do_hdr, do_hdr_size);
    sndbuf[18 + do_hdr_off] = 0x00;
    sndbuf[19 + do_hdr_off] = sizeof(data) + 2;
    sndbuf[20 + do_hdr_off] = 0xc0;
    sndbuf[21 + do_hdr_off] = 0x21;
    memcpy(sndbuf + do_hdr_size, data, sizeof(data));
    sndbuflen = do_hdr_size + sizeof(data);
    hdr.pkt = sndbuf;
    hdr.pkt_len = sndbuflen;

    while (1) {
      thc_pcap_check(p, (char *)intercept, NULL);
      usleep(100);
      if (passed <= time(NULL)) {
        if (thc_send_pkt(interface, (unsigned char *)&hdr, &sndbuflen) < 0) {
          fprintf(stderr, "Error: could not send packet to interface %s\n",
                  interface);
          return -1;
        }
        passed = time(NULL) + 15;
      }
    }
  } else {
    thc_pcap_function(interface, "it does not matter what we put here",
                      (char *)intercept, 1, NULL);
    fprintf(stderr, "Error: Could not set interface into promiscious mode\n");
    exit(-1);
  }

  return -1;  // never reached unless error
}
