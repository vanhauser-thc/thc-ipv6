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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "thc-ipv6.h"
#include "fps.h"

#define MAX_ALIVE 65536
#define MAX_NETS 1024
#define MAX_VENDID 64
#define MAX_PORTS 256
#define MAX_FOUR 16
#define TCP_OPT_LEN 28  // 20
#define FPS_INVALID "invalid packet data"
#define FPS_UNKNOWN "unknown"
#define RESP_PONG "ICMP echo-reply"
#define RESP_UNREACH_PORT "ICMP port unreachable"
#define RESP_UNREACH_ROUTE "ICMP network unreachable"
#define RESP_UNREACH_FW "ICMP firewalled unreachable"
#define RESP_UNREACH_OOSCOPE "ICMP out of scope unreachable"
#define RESP_UNREACH_ADDR "ICMP host unreachable"
#define RESP_UNREACH_GRESS "ICMP ingress/egress filter unreachable"
#define RESP_UNREACH_REJECT "ICMP route reject unreachable"
#define RESP_TOOBIG "ICMP packet too big"
#define RESP_TTLEXCEED "ICMP TTL exceeded"
#define RESP_REDIR "ICMP local router traffic redirect"
#define RESP_PARAMPROB "ICMP parameter problem"
#define RESP_ERROR "ICMP error"
#define RESP_UDP "UDP"
#define RESP_SYNACK "TCP SYN-ACK"
#define RESP_RST "TCP RST"
#define RESP_ACK "TCP ACK"
#define RESP_OTHER "TCP misc-options"
#define RESP_UNKNOWN "unknown"

extern int _thc_ipv6_rawmode;

struct fingerprint {
  char OS[1024];
  char FP[200];
};

static char   _fingerprint[4096];  // not thread safe!
unsigned char buf[8], *alive[MAX_ALIVE], *tagging = NULL;
int alive_no = 0, resolve = 0, waittime = 1, portscan = 0, curr = 0, list = 0,
    slow = 0;
int synports[MAX_PORTS], ackports[MAX_PORTS], udpports[MAX_PORTS];
int ndp_only = 0, do_ping = 1, do_dst = 1, do_hop = 0, verbose = 0,
    srcport = -1, do_help = 0, do_hopcount = 0, still_not_there = 0,
    rst_means_alive = 1;
unsigned long int tcount = 0;
FILE *            out = NULL;
struct hostent *  he = NULL;
short int         si, sp, sp2;

// all dict entries must start with a single from/to 0,0,0,0
// and end with a single from/to ffff,ffff,ffff,ffff
unsigned short int dict_small[] = {
    0, 0, 0, 0, /*to */ 0, 0, 0, 0, 0, 0, 0, 1, /*to */ 0, 0, 0,
    0x2ff,  // 1975 tests
    0, 0, 0, 0x300, /*to */ 0, 0, 0, 0x305, 0, 0, 0, 0x400, /*to */ 0, 0, 0,
    0x405, 0, 0, 0, 0x443, /*to */ 0, 0, 0, 0x445, 0, 0, 0, 0x500, /*to */ 0, 0,
    0, 0x505, 0, 0, 0, 0x530, /*to */ 0, 0, 0, 0x53f, 0, 0, 0, 0x555, /*to */ 0,
    0, 0, 0x555, 0, 0, 0, 0x600, /*to */ 0, 0, 0, 0x605, 0, 0, 0, 0x666,
    /*to */ 0, 0, 0, 0x667, 0, 0, 0, 0x700, /*to */ 0, 0, 0, 0x703, 0, 0, 0,
    0x800, /*to */ 0, 0, 0, 0x803, 0, 0, 0, 0x900, /*to */ 0, 0, 0, 0x903, 0, 0,
    0, 0xaaa, /*to */ 0, 0, 0, 0xaaa, 0, 0, 0, 0xc38, /*to */ 0, 0, 0, 0xc38, 0,
    0, 0, 0x9dd, /*to */ 0, 0, 0, 0x9dd, 0, 0, 0, 0xff0, /*to */ 0, 0, 0, 0xfff,
    0, 0, 0, 0x1000, /*to */ 0, 0, 0, 0x1111, 0, 0, 0, 0x1337, /*to */ 0, 0, 0,
    0x1337, 0, 0, 0, 0x14e9, /*to */ 0, 0, 0, 0x14e9, 0, 0, 0, 0x1a0b,
    /*to */ 0, 0, 0, 0x1a0b, 0, 0, 0, 0x1f40, /*to */ 0, 0, 0, 0x1f40, 0, 0, 0,
    0x1f90, /*to */ 0, 0, 0, 0x1f90, 0, 0, 0, 0x2000, /*to */ 0, 0, 0, 0x2111,
    0, 0, 0, 0x3000, /*to */ 0, 0, 0, 0x3011, 0, 0, 0, 0x3128, /*to */ 0, 0, 0,
    0x3128, 0, 0, 0, 0x2525, /*to */ 0, 0, 0, 0x2525, 0, 0, 0, 0x5353,
    /*to */ 0, 0, 0, 0x5353, 0, 0, 0, 0x6666, /*to */ 0, 0, 0, 0x6667, 0, 0, 0,
    0x8000, /*to */ 0, 0, 0, 0x8000, 0, 0, 0, 0x8080, /*to */ 0, 0, 0, 0x8080,
    0, 0, 0, 0xaaaa, /*to */ 0, 0, 0, 0xaaaa, 0, 0, 0, 0xabcd, /*to */ 0, 0, 0,
    0xabcd, 0, 0, 0, 0xbabe, /*to */ 0, 0, 0, 0xbabe, 0, 0, 0, 0xbeef,
    /*to */ 0, 0, 0, 0xbeef, 0, 0, 0, 0xcafe, /*to */ 0, 0, 0, 0xcafe, 0, 0, 0,
    0xc0de, /*to */ 0, 0, 0, 0xc0de, 0, 0, 0, 0xdead, /*to */ 0, 0, 0, 0xdead,
    0, 0, 0, 0xf500, /*to */ 0, 0, 0, 0xf500, 0, 0, 0, 0xfeed, /*to */ 0, 0, 0,
    0xfeed, 0, 0, 0, 0xfff0, /*to */ 0, 0, 0, 0xffff, 0, 0, 1, 0, /*to */ 0, 0,
    1, 0x1ff, 0, 0, 2, 0, /*to */ 0, 0, 0x1bb, 5, 0, 0, 2, 6, /*to */ 0, 0, 9,
    9, 0, 0, 2, 0xa, /*to */ 0, 0, 2, 0x20, 0, 0, 2, 0x21, /*to */ 0, 0, 3,
    0x21, 0, 0, 2, 0x22, /*to */ 0, 0, 3, 0x22, 0, 0, 2, 0x25, /*to */ 0, 0, 9,
    0x25, 0, 0, 2, 0x50, /*to */ 0, 0, 9, 0x50, 0, 0, 2, 0x53, /*to */ 0, 0, 9,
    0x53, 0, 0, 2, 0x80, /*to */ 0, 0, 9, 0x80, 0, 0, 2, 0x1bb, /*to */ 0, 0, 9,
    0x1bb, 0, 0, 2, 0x500, /*to */ 0, 0, 9, 0x500,
    //  0, 0, 0xa, 0, /*to */ 0, 0, 0xf, 2,
    0, 0, 0x80, 6, /*to */ 0, 0, 0x80, 0x1f, 0, 0, 0x200, 0, /*to */ 0, 0,
    0x200, 3, 0, 0, 0x389, 0, /*to */ 0, 0, 0x389, 3, 0, 0, 0x443, 0, /*to */ 0,
    0, 0x443, 3, 0, 0, 0x500, 0, /*to */ 0, 0, 0x500, 2, 0, 0, 0x666, 0,
    /*to */ 0, 0, 0x669, 2, 0, 0, 0x3128, 0, /*to */ 0, 0, 0x3128, 3, 0, 0,
    0x6666, 0, /*to */ 0, 0, 0x6669, 2, 0, 0, 0x8080, 0, /*to */ 0, 0, 0x8080,
    3, 0, 0, 0xdead, 0xbeef, /*to */ 0, 0, 0xdead, 0xbeef,
    //  0, 1, 0, 0, /*to */ 0, 3, 3, 3,
    0, 0, 0, 0, /*to */ 4, 4, 4, 4,  // 24 doubles here == 0.42%
    1, 0, 0, 5, /*to */ 1, 0, 0, 0xf,
    //  2, 0, 1, 0, /*to */ 2, 0, 1, 3,
    2, 0, 0, 5, /*to */ 2, 0, 0, 0xd,
    //  1, 2, 3, 4, /*to */ 1, 2, 3, 4,
    5, 0, 0, 1, /*to */ 0xff, 0, 0, 2, 0xffff, 0x00ff, 0xfe00, 0xfffe,
    /*to */ 0xffff, 0x00ff, 0xfe00, 0xffff, 0xffff, 0xffff, 0xffff, 0xfffe,
    /*to */ 0xffff, 0xffff, 0xffff, 0xfffe, 0xffff, 0xffff, 0xffff, 0xffff,
    /*to */ 0xffff, 0xffff, 0xffff, 0xffff};

unsigned short int dict_large[] = {
    0, 0, 0, 0, /*to */ 0, 0, 0, 0, 0, 0, 0, 1, /*to */ 0, 0, 1,
    0x2fff,  // 1975 tests
    0, 0, 0, 0x3000, /*to */ 0, 0, 1, 0x3333, 0, 0, 0, 0x5353, /*to */ 0, 0, 2,
    0x5353, 0, 0, 0, 0x6666, /*to */ 0, 0, 2, 0x6667, 0, 0, 0, 0x8000,
    /*to */ 0, 0, 2, 0x8000, 0, 0, 0, 0x8080, /*to */ 0, 0, 2, 0x8080, 0, 0, 0,
    0xaaaa, /*to */ 0, 0, 2, 0xaaaa, 0, 0, 0, 0xabcd, /*to */ 0, 0, 2, 0xabcd,
    0, 0, 0, 0xbabe, /*to */ 0, 0, 2, 0xbabe, 0, 0, 0, 0xbeef, /*to */ 0, 0, 2,
    0xbeef, 0, 0, 0, 0xcafe, /*to */ 0, 0, 2, 0xcafe, 0, 0, 0, 0xc0de,
    /*to */ 0, 0, 2, 0xc0de, 0, 0, 0, 0xdead, /*to */ 0, 0, 2, 0xdead, 0, 0, 0,
    0xf500, /*to */ 0, 0, 2, 0xf500, 0, 0, 0, 0xfeed, /*to */ 0, 0, 2, 0xfeed,
    0, 0, 0, 0xfff0, /*to */ 0, 0, 2, 0xffff, 0, 0, 2, 0, /*to */ 0, 0, 0x1bb,
    5, 0, 0, 2, 0x11, /*to */ 0, 0, 2, 0x100, 0, 0, 2, 0x1bb, /*to */ 0, 0, 9,
    0x1bb, 0, 0, 2, 0x500, /*to */ 0, 0, 9, 0x500, 0, 0, 2, 6, /*to */ 0, 0, 10,
    10, 0, 0, 0xa, 0, /*to */ 0, 0, 0xf, 5, 0, 0, 0x80, 6, /*to */ 0, 0, 0x80,
    0x1f, 0, 0, 0x200, 0, /*to */ 0, 0, 0x200, 5, 0, 0, 0x389, 0, /*to */ 0, 0,
    0x389, 5, 0, 0, 0x443, 0, /*to */ 0, 0, 0x443, 5, 0, 0, 0x500, 0, /*to */ 0,
    0, 0x500, 5, 0, 0, 0x666, 0, /*to */ 0, 0, 0x669, 5, 0, 0, 0x3128, 0,
    /*to */ 0, 0, 0x3128, 5, 0, 0, 0x6666, 0, /*to */ 0, 0, 0x6669, 5, 0, 0,
    0x8080, 0, /*to */ 0, 0, 0x8080, 5, 0, 0, 0xdead, 0xbeef, /*to */ 0, 0,
    0xdead, 0xbeef,
    //  0, 1, 0, 0, /*to */ 0, 3, 3, 3,
    0, 0, 0, 0, /*to */ 5, 5, 5, 5,  // some doubles here
    1, 0, 0, 6, /*to */ 1, 0, 0, 0x10,
    //  2, 0, 1, 0, /*to */ 2, 0, 1, 3,
    2, 0, 0, 5, /*to */ 2, 0, 0, 0x10,
    //  1, 2, 3, 4, /*to */ 1, 2, 3, 4,
    6, 0, 0, 0, /*to */ 0xff, 0, 0, 2, 0xffff, 0x00ff, 0xfe00, 0xfffe,
    /*to */ 0xffff, 0x00ff, 0xfe00, 0xffff, 0xffff, 0xffff, 0xffff, 0xfffe,
    /*to */ 0xffff, 0xffff, 0xffff, 0xfffe, 0xffff, 0xffff, 0xffff, 0xffff,
    /*to */ 0xffff, 0xffff, 0xffff, 0xffff};

unsigned short int *dict = NULL;

unsigned char tcp_opt[TCP_OPT_LEN] = {0x02, 0x04, 0xff, 0xff, 0x04, 0x02, 0x08,
                                      0x0a, 0x00, 0x09, 0x00, 0x09, 0x00, 0x00,
                                      0x00, 0x00, 0x01, 0x03, 0x03, 0xff, 0x06,
                                      0x06, 0xb0, 0x0b, 0xba, 0xbe, 0x01, 0x01};

// more keywords:
// cafe, dead, beef, affe, b00b, babe, f00, fefe, ffff, 1337, 666, 0, 1

void help(char *prg) {
  printf("%s %s (c) 2020 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf(
      "Syntax: %s [-CFHLMPSdlpvV] [-I srcip6] [-i file] [-o file] [-e opt] [-s "
      "port,..] [-a port,..] [-u port,..] [-T tag] [-W TIME] interface "
      "[unicast-or-multicast-address [remote-router]]\n\n",
      prg);
  printf("Options:\n");
  if (do_help) printf(" Output Options:\n");
  printf("  -i file    check systems from input file\n");
  printf("  -o file    write results to output file\n");
  if (do_help)
    printf(
        "  -v         verbose information (twice: detailed, thrice: dumping "
        "packets)\n");
  if (do_help > 1) printf("  -V         enable debug output\n");
  printf("  -d         DNS resolve alive IPv6 addresses\n");
  if (do_help > 1) printf("  -H         print hop count of received packets\n");
  if (do_help) printf(" Enumerate Options:\n");
  printf(
      "  -M         enumerate hardware addresses (MAC) from input addresses "
      "(slow!)\n");
  printf(
      "  -C         enumerate common addresses of input networks, -CC for "
      "large scan\n");
  printf(
      "  -4 ipv4/range  test various IPv4 address encodings per network (eg "
      "1.2.3.4/24)\n");
  if (do_help > 1)
    printf(
        "  -y step    for range scans (2000::0-f), define the step range "
        "(default: 1)\n");
  if (do_help) printf(" Alive Technique Options:\n");
  printf("  -p         send a ping packet for alive check (default)\n");
  printf(
      "  -e dst,hop send an errornous packets: destination (default), "
      "hop-by-hop\n");
  printf(
      "  -s port,port,..  TCP-SYN packet to ports for alive check or "
      "\"portscan\"\n");
  printf("  -a port,port,..  TCP-ACK packet to ports for alive check\n");
  printf("  -u port,port,..  UDP packet to ports for alive check\n");
  if (do_help)
    printf(
        "  -F         firewall mode: -p -e dst -u 53 -s 22,25,80,443,9511 -a "
        "9511\n");
  if (do_help > 1)
    printf(
        "  -R         do not consider TCP-RST as alive (good with firewalls, "
        "e.g. -F)\n");
  if (do_help) printf(" Sending Options\n");
  if (do_help) {
    printf(
        "  -n number  how often to send each packet (default: local 1, remote "
        "2)\n");
    printf(
        "  -W time    time in ms to wait after sending a packet (default: "
        "%d)\n",
        waittime);
    printf(
        "  -S         slow mode, get best router for each remote target or "
        "when proxy-NA\n");
    printf(
        "  -I src[/mask]  use the specified IPv6 address as source. Use mask "
        "for random.\n");
    printf(
        "  -l         use link-local address for multicast addresses instead "
        "of global\n");
    printf(
        "  -P         only print addresses that would be scanned, no packets "
        "are sent!\n");
    if (do_help > 1) {
      printf(
          "  -L         local mode - perform only NDP and report local systems "
          "alive\n");
      printf(
          "  -r         renew IPv6 src address for every new target (waits if "
          "none there)\n");
      printf("  -T tag     put tag string in ICMP packets\n");
      printf("  -x port    TCP/UDP src port for -s, -a and -u\n");
      printf("  -Z mac     use given destination mac address\n");
    }
    printf(
        "  -m         raw mode (for network adapters where you do not have "
        "Ethernet)\n");
  }
  if (do_help == 1) {
    printf(" Help Options:\n");
    printf("  -hh        show even more options\n");
  } else
    printf(
        "  -h         to display more command line options and help (-hh: more "
        "options)\n");
  printf(
      "\nTarget address on command line or in input file can include ranges in "
      "the form\n");
  printf("of 2001:db8::1-fff or 2001:db8::1-2:0-ffff:0:0-ffff, etc.\n");
  if (do_help) {
    printf("Do not use the ranges (from-to) option with -M, -C or -4.\n");
    printf(
        "If you use SYN packets (-s/-F option), automatic OS detection is "
        "performed.\n");
    //    printf("If you specify a remote router, fragmentation+srcroute is
    //    performed.\n");
    printf(
        "Returns -1 on errors, 0 if a system was found alive or 1 if nothing "
        "was found.\n");
  }
  exit(-1);
}

/*****************************************************************************************/

/*
    Copyright (c) warlord @ nologin.org.  All rights reserved.
    For more information, please visit http://www.nologin.org
 */

char *get_OS(char *query_fp) {
  int i = 0;

  for (i = 0; i < sizeof(fingerprintsArray) / sizeof(fingerprintsArray[0]);
       i++) {
    if (strcmp(fingerprintsArray[i].fingerprint, query_fp) == 0)
      return fingerprintsArray[i].OS;
  }

  return FPS_UNKNOWN;
}

char *warlord_checkFingerprint(char *buffer, int len) {
  char *os, *end, *ptr, ip_mod, ip_ver = 0, ip_hdr_size = 0;

  ip_ver = (((unsigned char)buffer[0] & 0xf0) >> 4);
  if (ip_ver == 4) {
    ip_mod = 0;
    ip_hdr_size = ((buffer[0] & 0x0f) << 2);
  } else if (ip_ver == 6) {
    ip_mod = 20;  // to align packet sizes in FPS with IPv4 for IPv6 (would be
                  // 40 bytes - 20 = 20 equals to IPv4)
    ip_hdr_size = 40;
  }

  if (ip_ver == 0 || (len - ip_hdr_size) < 20 || ip_hdr_size < 20 ||
      ip_hdr_size > 40)  // invalid ip version or packet too short?
    return FPS_INVALID;

  snprintf(
      _fingerprint, sizeof(_fingerprint) - 1, "%04x:%02x:%04x",
      len + 20 -
          ip_hdr_size,  // total length (calculated with assumed ipv4 header
      (unsigned char)buffer[ip_hdr_size + 12],          // header length
      ntohs(*(in_port_t *)&buffer[ip_hdr_size + 14]));  // window size

  // So what kind of tcp options did we receive?
  // This is being used for OS fingerprinting
  end = &buffer[len];
  if (len > ip_hdr_size + (unsigned char)buffer[ip_hdr_size + 12])
    end = &buffer[ip_hdr_size + (unsigned char)buffer[ip_hdr_size + 12]];
  for (ptr = &buffer[ip_hdr_size + 20]; ptr < end;) {
    switch (*ptr) {
      case 0x0:  // end of options
        ptr = end;
        break;
      case 0x1:  // some pad entire options portion with NOP to keep response
                 // option size the same
        strncat(_fingerprint, ":NOP",
                sizeof(_fingerprint) - strlen(_fingerprint) - 1);
        ptr++;
        break;
      case 0x2:  // segment size
        snprintf(&_fingerprint[strlen(_fingerprint)],
                 sizeof(_fingerprint) - strlen(_fingerprint), ":SS%04x",
                 ntohs(*(in_port_t *)(ptr + 2)));
        ptr += 4;
        break;
      case 0x3:  // window scaling
        strncat(_fingerprint, ":WSxx",
                sizeof(_fingerprint) - strlen(_fingerprint) - 1);
        ptr += 3;
        break;
      case 0x4:  // Sack Permitted / Sack Denied
        switch (ptr[1]) {
          case 0x2:
            strncat(_fingerprint, ":SP",
                    sizeof(_fingerprint) - strlen(_fingerprint) - 1);
            break;
          default:
            strncat(_fingerprint, ":SD",
                    sizeof(_fingerprint) - strlen(_fingerprint) - 1);
            break;
        }
        ptr += 2;
        break;
      case 0x6:  // echo request
        strncat(_fingerprint, ":PI",
                sizeof(_fingerprint) - strlen(_fingerprint) - 1);
        ptr += 6;
        break;
      case 0x7:  // echo reply
        strncat(_fingerprint, ":PO",
                sizeof(_fingerprint) - strlen(_fingerprint) - 1);
        ptr += 6;
        break;
      case 0x8:  // Time stamp
        strncat(_fingerprint, ":TS",
                sizeof(_fingerprint) - strlen(_fingerprint) - 1);
        ptr += 10;
        break;
      default:  // unknown
        snprintf(&_fingerprint[strlen(_fingerprint)],
                 sizeof(_fingerprint) - strlen(_fingerprint), ":UOP%02x",
                 (unsigned char)(*ptr));
        ptr += (unsigned char)ptr[1];
        break;
    }
  }
  _fingerprint[sizeof(_fingerprint) - 1] = 0;
  //              printf ("%s\t\tport %5d\t", inet_ntoa (src), ntohs
  //              (recvtcp->source));
  os = get_OS(_fingerprint);

  if (strcmp(os, FPS_UNKNOWN) == 0) return _fingerprint;

  return os;
}

/* end of warlords code */
/**************************************************************************/

void check_packets(u_char *foo, const struct pcap_pkthdr *header,
                   const unsigned char *data) {
  int            i, ok = 0, len = header->caplen, offset = 0, nxt;
  unsigned char *ptr = (unsigned char *)data, *p1, *p2, *p3, sport[16] = "",
                *orig_dst = NULL;
  char *type = RESP_UNKNOWN, hopcount[20] = "", *os = NULL;

  if (do_hdr_size) {
    ptr += do_hdr_size;
    len -= do_hdr_size;
    if ((ptr[0] & 240) != 0x60) return;
  } else if (_thc_ipv6_rawmode == 0) {
    ptr += 14;
    len -= 14;
  }

  if (debug) thc_dump_data(ptr, len, "Received Packet");

  if (len < 48 + sizeof(buf)) return;

  nxt = ptr[6];

  // if the destination system sends source routed packets back, unlikely though
  //  if (ptr[6] == NXT_ROUTE)
  //    if ((offset = (ptr[41] + 1) * 8) + 48 + sizeof(buf) > len)
  //      return;

  if (ptr[6 + offset] == NXT_FRAG) {
    nxt = ptr[40 + offset];
    offset += 8;
  }

  if (still_not_there == 1) still_not_there = 0;

  if (nxt == NXT_ICMP6 && (do_ping || do_dst || do_hop || udpports[0] != -1)) {
    if (ptr[40 + offset] == ICMP6_PINGREPLY && (do_ping || do_dst || do_hop)) {
      if (tagging == NULL) {
        if (memcmp(ptr + 50 + offset, (char *)&si + _TAKE2, 2) == 0) {
          ok = 1;
          type = RESP_PONG;
        }
      } else {
        // printf("TAG: %s\n", ptr + 48 + offset);
        if (memcmp(ptr + 48 + offset, (char *)tagging, strlen(tagging)) == 0) {
          ok = 1;
          type = RESP_PONG;
        }
      }
    } else  // if not a ping reply, its an error packet and the size is larger
        if (len < 96 + sizeof(buf))
      return;
    if (ptr[40 + offset] == ICMP6_PARAMPROB && (do_dst || do_hop))
      if (memcmp(ptr + len - 4, (char *)&si + _TAKE2, 2) == 0) {
        if (list == 0 && do_hop)
          ok = 2;
        else
          ok = 1;
        type = RESP_PARAMPROB;
      }
    if (ptr[40 + offset] == ICMP6_UNREACH && ptr[41 + offset] == 4 &&
        udpports[0] != -1)
      if (memcmp(ptr + 88 + offset, (char *)&sp2 + _TAKE2, 2) == 0) {
        ok = 1;
        type = RESP_UNREACH_PORT;
        i = (ptr[90 + offset] << 8) + ptr[91 + offset];
        snprintf(sport, sizeof(sport), "%d/", i);
      }
  }

  if (nxt == NXT_UDP && udpports[0] != -1)
    if (memcmp(ptr + 42 + offset, (char *)&sp2 + _TAKE2, 2) == 0) {
      ok = 1;
      type = RESP_UDP;
    }

  if (nxt == NXT_TCP && (portscan || synports[0] != -1 || ackports[0] != -1))
    if (memcmp(ptr + 42 + offset, (char *)&sp2 + _TAKE2, 2) == 0) {
      ok = 1;
      i = ptr[41 + offset] + (ptr[40 + offset] << 8);
      snprintf(sport, sizeof(sport), "%d/", i);
      switch (ptr[53 + offset]) {
        case (TCP_SYN + TCP_ACK):
          os = warlord_checkFingerprint(ptr, len);
          type = RESP_SYNACK;
          break;
        case TCP_ACK:
          type = RESP_ACK;
          break;
        case TCP_RST: /* fall through */
        case (TCP_RST + TCP_ACK):
          type = RESP_RST;
          if (rst_means_alive == 0) ok = 0;
          break;
        default:
          type = RESP_OTHER;
      }
    }

  if (ok == 0 && nxt == NXT_ICMP6) {
    ok = 2;
    switch (ptr[40 + offset]) {
      case 1:
        switch (ptr[41 + offset]) {
          case 0:
            type = RESP_UNREACH_ROUTE;
            break;
          case 1:
            type = RESP_UNREACH_FW;
            break;
          case 2:
            type = RESP_UNREACH_OOSCOPE;
            break;
          case 3:
            type = RESP_UNREACH_ADDR;
            break;
          case 4:
            type = RESP_UNREACH_PORT;
            break;
          case 5:
            type = RESP_UNREACH_GRESS;
            break;
          case 6:
            type = RESP_UNREACH_REJECT;
            break;
          default:
            ok = 0;
        }
        break;
      case 2:
        type = RESP_TOOBIG;
        break;
      case 3:
        type = RESP_TTLEXCEED;
        break;
      case 4:
        type = RESP_PARAMPROB;
        break;
      case 137:
        type = RESP_REDIR;
        break;
      default:
        ok = 0;
    }
    if (ok == 0) {
      if (slow == 0 || ptr[40] != ICMP6_NEIGHBORADV) {
        type = RESP_ERROR;
        snprintf(sport, sizeof(sport), "%d:%d/", ptr[40], ptr[41]);
        ok = 2;
      }
    } else
      orig_dst = thc_ipv62notation(ptr + 64 + offset + 8);
  }

  i = 0;
  if (verbose < 2)
    while (ok && i < alive_no) {
      if (memcmp(alive[i], ptr + 8 + offset, 16) == 0) ok = 0;
      i++;
    }

  if (ok) {
    if (do_hopcount) sprintf(hopcount, " {hop count: %d}", ptr[7]);
    if (portscan == 0 ||
        (portscan && (verbose > 2 || (strcmp(type, RESP_UNREACH_PORT) != 0 &&
                                      strcmp(type, RESP_UNREACH_FW) != 0)))) {
      if (resolve) he = gethostbyaddr(ptr + 8, 16, AF_INET6);
      p2 = thc_ipv62notation(ptr + 8);
      printf("Alive: %s%s%s%s [%s%s%s%s]%s%s%s%s\n", p2, resolve ? " (" : "",
             resolve && he != NULL ? he->h_name : "", resolve ? ")" : "", sport,
             type, orig_dst != NULL ? " for " : "",
             orig_dst != NULL ? (char *)orig_dst : "", hopcount,
             os == NULL ? "" : " (OS: ", os == NULL ? "" : os,
             os == NULL ? "" : ")");
      if (out != NULL)
        fprintf(out, "%s%s%s%s\n", p2, resolve ? " (" : "",
                (resolve && he != NULL) ? he->h_name : "", resolve ? ")" : "");
      free(p2);
      if (orig_dst != NULL) free(orig_dst);
      if (alive_no < MAX_ALIVE && (alive[alive_no] = malloc(16)) != NULL) {
        memcpy(alive[alive_no], ptr + 8, 16);
        alive_no++;
        if (alive_no == MAX_ALIVE)
          fprintf(stderr,
                  "Warning: more than %d alive systems detected, disabling "
                  "double results check!\n",
                  MAX_ALIVE);
      }
    }
  } else if (verbose && len >= 96 + sizeof(buf) && nxt == NXT_ICMP6 &&
             ptr[41 + offset] != 4 && ptr[40 + offset] < 4 &&
             ptr[40 + offset] > 0 && ptr[40 + 8 + offset + 6] == NXT_ICMP6) {
    if (memcmp(ptr + len - 4, (char *)&si + _TAKE2, 2) == 0) {
      if (resolve) he = gethostbyaddr(ptr + 8, 16, AF_INET6);
      p2 = thc_ipv62notation(ptr + 8);
      p3 = thc_ipv62notation(ptr + 24 + 40 + 8 + offset);
      switch (ptr[40 + offset]) {
        case 1:
          p1 = "unreachable";
          break;
        case 2:
          p1 = "toobig";
          break;
        case 3:
          p1 = "time-to-live-exceeded";
          break;
      }
      printf("Warning: %s%s%s%s sent an ICMP %s for %s\n", p2,
             resolve ? " (" : "", resolve && he != NULL ? he->h_name : "",
             resolve ? ")" : "", p1, p3);
      free(p2);
      free(p3);
    }
  }
  if (still_not_there == 0) {
    if (ok != 1)
      still_not_there = 1;
    else
      still_not_there = -1;
  }
}

void get_ports_from_cmdline(int ports[], char *plist, char param) {
  int  p, c = 0;
  char mylist[strlen(plist) + 1], *ptr, *ptr2;

  if (strtok(plist, "0123456789,") != NULL) {
    fprintf(stderr,
            "Error: ports must be defined by numbers and separated by a comma, "
            "e.g. \"-%c 22,53,80\"\n",
            param);
    exit(-1);
  }
  strcpy(mylist, plist);
  ptr = mylist;
  do {
    if (c >= MAX_PORTS) {
      fprintf(stderr, "Error: a maximum number of %d ports can be specified\n",
              MAX_PORTS);
      exit(-1);
    }
    if ((ptr2 = index(ptr, ',')) != NULL) *ptr2++ = 0;
    p = atoi(ptr);
    if (p < 0 || p > 65535) {  // allow port zero
      fprintf(stderr, "Error: ports must be between 0 and 65535: %s\n", ptr);
      exit(-1);
    }
    ports[c] = p % 65536;
    c++;
    ptr = ptr2;
  } while (ptr2 != NULL);
}

int adress4to6(unsigned char *addr6, unsigned int addr4, char *state) {
  unsigned char a, b, c, d;

  a = (addr4 >> 24) % 256;
  b = (addr4 >> 16) % 256;
  c = (addr4 >> 8) % 256;
  d = addr4 % 256;

  memset(addr6 + 8, 0, 8);

  switch (*state) {
    case 0:
      addr6[15] = d;
      break;
    case 1:
      if (d > 9) {  // is hex different to decimal?
        addr6[14] = (d / 100);
        d = d % 100;
        if (d > 9) d = (d / 10) * 16 + (d % 10);
        addr6[15] = d;

        break;

      } else
        *state += 1;  // otherwise fall through
    case 2:
      addr6[9] = a;
      addr6[11] = b;
      addr6[13] = c;
      addr6[15] = d;
      break;
    case 3:
      if (d > 9 || c > 9 || b > 9 || a > 9) {  // is hex different to decimal?

        addr6[8] = (a / 100);
        a = a % 100;
        if (a > 9) a = (a / 10) * 16 + (a % 10);
        addr6[9] = a;

        addr6[10] = (b / 100);
        b = b % 100;
        if (b > 9) b = (b / 10) * 16 + (b % 10);
        addr6[11] = b;

        addr6[12] = (c / 100);
        c = c % 100;
        if (c > 9) c = (c / 10) * 16 + (c % 10);
        addr6[13] = c;

        addr6[14] = (d / 100);
        d = d % 100;
        if (d > 9) d = (d / 10) * 16 + (d % 10);
        addr6[15] = d;

        break;

      } else
        *state += 1;  // otherwise fall through
    case 4:
      addr6[12] = a;
      addr6[13] = b;
      addr6[14] = c;
      addr6[15] = d;
      *state += 1;
      return 1;  // end of state reached
      break;     // not reached
    default:
      fprintf(stderr, "Error: invalid address4to6 state %d!\n", *state);
      exit(-1);
  }
  *state += 1;
  return 0;
}

int main(int argc, char *argv[]) {
  unsigned char  string[128];  // = "ip6 and dst ";
  unsigned char *pkt = NULL, *router6 = NULL, *cur_dst, *p2, *p3, *ptr3, *smac,
                buf2[6];
  unsigned char *multicast6 = NULL, *src6 = NULL, *mac = NULL, *rmac = NULL,
                *routers[2];
  int pkt_len = 0, prefer = PREFER_GLOBAL, fromto = 0, dictptr = 0, offset = 14,
      step = 1;
  int enumerate_mac = 0, enumerate_dhcp = 0, i, j, k, l, cur_enum = 0,
      print_only = 0, rand_source = 0;
  int no_vendid = 0, no_nets = 0, local = -1, no_send = 1, no_send_local = 1,
      no_send_remote = 2, nos = 0, renew = 0, errcnt, sendrc;
  char *interface = NULL, *input = NULL, *output = NULL, line[128], line2[128],
       *ptr, *ptr2, do_router = 0, ok;
  unsigned int  four_from[MAX_FOUR], four_to[MAX_FOUR], addr_cur;
  unsigned char fcnt = 0, bh, bm, bl, restart, use_dmac = 0, dump_all = 0,
                inc_next = 0, inc_step = 1;
  unsigned int ip1, ip2, ip3, ip4, cip1, cip2, cip3, cip4, cip5, cip6, cip7,
      cip8;
  unsigned int fip1, fip2, fip3, fip4, fip5, fip6, fip7, fip8, tip1, tip2, tip3,
      tip4, tip5, tip6, tip7, tip8;
  unsigned char vendid[MAX_VENDID][11], nets[MAX_NETS][8], orig_dst[16],
      dmac[27] = {0, 0, 0, 0, 0, 0, 0};
  in_addr_t addr4;
  //  unsigned char dns4buf[] = { 0xde, 0xad, 0x01, 0x00, 0x00, 0x01, 0x00,
  //  0x00,
  //                    0x00, 0x00, 0x00, 0x00, 0x09, 0x6c, 0x6f, 0x63, 0x61,
  //                    0x6c, 0x68, 0x6f, 0x73, 0x74, 0x00, 0x00, 0x01, 0x00,
  //                    0x01 };
  unsigned char dns6buf[] = {0xba, 0xbe, 0x01, 0x00, 0x00, 0x01, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x6c,
                             0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73,
                             0x74, 0x00, 0x00, 0x1c, 0x00, 0x01};
  thc_ipv6_hdr *hdr;
  time_t        passed;
  pcap_t *      p;
  FILE *        in = NULL;
  time_t        timeval;

  for (i = 0; i < MAX_PORTS; i++)
    udpports[i] = ackports[i] = synports[i] = -1;

  if (argc == 1) help(argv[0]);

  j = 0;
  while ((i = getopt(argc, argv,
                     "CRhH4:W:w:PSLFdrlMDn:i:o:pvs:a:u:e:VZ:I:Xx:y:T:")) >= 0) {
    switch (i) {
      case 'h':
        do_help++;
        break;  // not reached
      case 'H':
        do_hopcount = 1;
        break;
      case 'R':
        rst_means_alive = 0;
        break;
      case 'P':
        print_only = 1;
        break;
      case '4':
        if (fcnt >= MAX_FOUR) {
          fprintf(stderr,
                  "Error: maximum number of IPv4 addresses supported is %d!\n",
                  MAX_FOUR);
          exit(-1);
        }
        if ((ptr = index(optarg, '/')) == NULL) {
          if ((addr4 = inet_addr(optarg)) == 0xffffffff) {
            fprintf(stderr, "Error: option is not a valid IPv4 address: %s\n",
                    optarg);
            exit(-1);
          }
          four_from[fcnt] = htonl(addr4);
          four_to[fcnt] = htonl(addr4);
          fcnt++;
        } else {
          if ((ptr2 = malloc(strlen(optarg) + 1)) == NULL) {
            fprintf(stderr, "Error: can not allocate memory\n");
            exit(-1);
          }
          strcpy(ptr2, optarg);
          k = 32;
          if ((ptr = index(ptr2, '/')) != NULL) *ptr++ = 0;
          if ((k = atoi(ptr)) < 8 || k > 31) {
            fprintf(stderr,
                    "Error: network size may only be between /8 and /31: %s\n",
                    optarg);
            exit(-1);
          }
          if ((addr4 = htonl(inet_addr(ptr2))) == 0xffffffff) {
            fprintf(stderr, "Error: option is not a valid IPv4 address: %s\n",
                    ptr2);
            exit(-1);
          }
          free(ptr2);
          l = 1 << (32 - k);
          l--;
          four_to[fcnt] = (addr4 | l);
          l = 0xffffffff - l;
          four_from[fcnt] = (addr4 & l);
          fcnt++;
        }
        break;
      case 'T':
        tagging = optarg;
        break;
      case 'Z':
        use_dmac = 1;
        sscanf(optarg, "%x:%x:%x:%x:%x:%x", (unsigned int *)&dmac[0],
               (unsigned int *)&dmac[1], (unsigned int *)&dmac[2],
               (unsigned int *)&dmac[3], (unsigned int *)&dmac[4],
               (unsigned int *)&dmac[5]);
        break;
      case 'w':
      case 'W':
        waittime = atoi(optarg) * 1000;
        break;
      case 'S':
        slow = 1;
        break;
      case 'L':
        ndp_only = 1;
        break;
      case 'V':
        debug = 1;
        break;
      case 'F':
        do_ping = 1;
        do_dst = 1;
        udpports[0] = 53;
        ackports[0] = 9511;
        synports[0] = 22;
        synports[1] = 25;
        synports[2] = 80;
        synports[3] = 443;
        synports[4] = 9511;
        break;
      case 'd':
        resolve = 1;
        break;
      case 'r':
        renew = 1;
        break;
      case 'l':
        prefer = PREFER_LINK;
        break;
      case 'm':
        thc_ipv6_rawmode(1);
        break;
      case 'M':
        enumerate_mac = 1;
        break;
      case 'C':
      case 'D':
        enumerate_dhcp = 1;
        if (dict == NULL)
          dict = dict_small;
        else
          dict = dict_large;
        break;
      case 'n':
        no_send_local = no_send_remote = atoi(optarg);
        break;
      case 'I':
        if ((src6 = thc_resolve6(optarg)) == NULL) {
          fprintf(stderr, "Error: unable to resolve IPv6 source address %s\n",
                  optarg);
          exit(-1);
        }
        if (index(optarg, '/') != NULL) {
          if ((p2 = strdup(optarg)) == NULL) {
            fprintf(stderr, "Error: malloc()\n");
            exit(-1);
          }
          p3 = index(p2, '/');
          *p3++ = 0;
          if ((i = atoi(p3)) < 8 || i > 120 || i % 8 != 0) {
            fprintf(stderr,
                    "Error: -I netmask parameter must be a multiple of 8\n");
            exit(-1);
          }
          rand_source = 16 - (i / 8);
        }
        break;
      case 'i':
        input = optarg;
        list++;
        if (curr == 0) curr = 1;
        break;
      case 'o':
        output = optarg;
        break;
      case 'p':
        do_ping = 1;
        j = (j | 1);
        break;
      case 'v':
        verbose++;
        break;
      case 's':
        j = (j | 8);
        if (strcasecmp(optarg, "xxx") == 0 ||
            strncasecmp(optarg, "port", 4) == 0 ||
            strncasecmp(optarg, "scan", 4) == 0) {
          portscan = 1;
          if (verbose < 2) verbose = 2;
        } else
          get_ports_from_cmdline(synports, optarg, 's');
        break;
      case 'a':
        j = (j | 8);
        get_ports_from_cmdline(ackports, optarg, 'a');
        break;
      case 'u':
        j = (j | 8);
        get_ports_from_cmdline(udpports, optarg, 'u');
        break;
      case 'e':
        if (index(optarg, ',') != 0) {
          do_dst = 1;
          do_hop = 1;
          j = (j | 6);
        } else {
          if (strncasecmp(optarg, "dst", 3) == 0 ||
              strncasecmp(optarg, "dest", 4) == 0) {
            do_dst = 1;
            j = (j | 4);
          }
          if (strncasecmp(optarg, "hop", 3) == 0) {
            do_hop = 1;
            j = (j | 2);
          }
          if (do_hop + do_dst == 0) {
            fprintf(stderr,
                    "Error: unknown options to error packet option: %s\n",
                    optarg);
            exit(-1);
          }
        }
        break;
      case 'X':
        dump_all = 1;
        break;
      case 'x':
        srcport = atoi(optarg);
        if (srcport < 0 || srcport > 65535) {
          fprintf(stderr, "Error: invalid port: %s\n", optarg);
          exit(-1);
        }
        break;
      case 'y':
        step = atoi(optarg);
        if (step < 1 || step > 256) {
          fprintf(stderr, "Error: invalid step range (valid: 1-256): %s\n",
                  optarg);
          exit(-1);
        }
        break;
      default:
        fprintf(stderr, "Error: unknown option -%c\n", i);
        exit(-1);
    }
  }

  if (do_help) help(argv[0]);

  if (slow && ndp_only) {
    fprintf(stderr, "Error: you can not use the -S and -L options together!\n");
    exit(-1);
  }

  if (j) {  // reset defaults if an alive check type was chosen
    if ((j & 1) == 0) do_ping = 0;
    if ((j & 2) == 0) do_hop = 0;
    if ((j & 4) == 0) do_dst = 0;
  }

  if (verbose > 1)
    fprintf(stderr,
            "Warning: -vv disables duplicate checks, every packet will be "
            "logged.\n");

  if (no_send < 1 || no_send > 10) {
    fprintf(stderr, "Error: -n option may only be set between 1 and 10\n");
    exit(-1);
  }
  if (waittime < 0) {
    fprintf(stderr, "Error: -W wait time is not a positive value\n");
    exit(-1);
  }

  if (do_hdr_size) offset = do_hdr_size;

  interface = argv[optind];
  if (argv[optind + 1] != NULL && argc >= optind + 2) {
    ptr = argv[optind + 1];
    curr = 0;
  } else
    ptr = "ff02::1";
  if (ptr !=
      NULL) {  // && (index(ptr, ':') == NULL || index(ptr, '-') == NULL)) {
    if (verbose > 1) printf("Resolving %s ...\n", ptr);
    if (index(ptr, '/') != NULL)
      fprintf(
          stderr,
          "Warning: network mask is ignored and processed as single host: %s\n",
          ptr);
    multicast6 = thc_resolve6(ptr);  // if it cant resolve - no problem
  }
  if (interface == NULL) {
    fprintf(stderr, "Error: no interface defined!\n");
    exit(-1);
  }
  if (multicast6 != NULL && multicast6[0] == 0xfe && multicast6[1] == 0x80)
    prefer = PREFER_LINK;
  if (src6 == NULL) {
    i = _thc_ipv6_showerrors;
    if (multicast6 != NULL && multicast6[0] == 0xff && multicast6[1] == 0x02)
      _thc_ipv6_showerrors = 0;
    if ((src6 = thc_get_own_ipv6(interface, multicast6, prefer)) == NULL) {
      fprintf(stderr, "Error: no IPv6 address found for interface %s!\n",
              interface);
      exit(-1);
    }
    _thc_ipv6_showerrors = i;
  }
  if ((smac = thc_get_own_mac(interface)) == NULL) {
    fprintf(stderr, "Error: no mac address found for interface %s!\n",
            interface);
    exit(-1);
  }
  if (verbose)
    printf("Selected source address %s to scan %s\n", thc_ipv62notation(src6),
           ptr);
  if (argv[optind + 2] != NULL && argc >= optind + 3) {
    if (verbose > 1) printf("Resolving %s ...\n", argv[optind + 2]);
    router6 = thc_resolve6(argv[optind + 2]);
    do_router = 1;
    if (use_dmac)
      mac = dmac;
    else if ((mac = thc_get_mac(interface, src6, router6)) == NULL) {
      fprintf(
          stderr,
          "Error: could not resolve mac address for destination router %s\n",
          argv[optind + 2]);
      exit(-1);
    }
  }
  // strcat(string, thc_ipv62notation(src6));
  // thc_dump_data(src6, 16, "SRC6");
  if (rand_source || renew != 0)
    strcpy(string, "ip6");
  else
    sprintf(string, "dst %s", thc_ipv62notation(src6));
  if (dump_all == 0) {
    strcat(string, " and ");
    if (portscan || synports[0] != -1 || udpports[0] != -1 ||
        ackports[0] != -1) {
      strcat(string, "( icmp6 or ");
      if (udpports[0] != -1) strcat(string, "udp ");
      if (udpports[0] != -1 &&
          (portscan || synports[0] != -1 || ackports[0] != -1))
        strcat(string, "or ");
      if (portscan || synports[0] != -1 || ackports[0] != -1)
        strcat(string, "tcp ");
      strcat(string, ")");
    } else
      strcat(string, "icmp6");
  }

  if (multicast6 != NULL && (enumerate_mac || enumerate_dhcp) &&
      input == NULL && multicast6[0] == 0xff) {
    fprintf(stderr,
            "Warning: -M/-C options make no sense for multicast addresses and "
            "are ignored for these\n");
    enumerate_dhcp = enumerate_mac = 0;
  }
  // make the sending buffer unique
  si = getpid() % 65536;
  if (srcport == -1) {
    sp = 1200 + si % 30000;
    sp2 = htons(sp);
  } else {
    sp = srcport;
    sp2 = htons(srcport);
  }
  memset(vendid, 0, sizeof(vendid));
  memset(nets, 0, sizeof(nets));
  memset(buf2, 0, sizeof(buf2));
  memset(buf, 0, sizeof(buf));
  buf2[0] = NXT_INVALID;
  buf2[1] = 1;
  if (tagging == NULL) {
    for (i = 0; i < sizeof(buf) / 2; i++)
      memcpy(buf + i * 2, (char *)&si + _TAKE2, 2);
  } else {
    if (strlen(tagging) > 8) tagging[8] = 0;
    for (i = 0; i < (sizeof(buf) / strlen(tagging)); i++)
      memcpy(buf + i * (strlen(tagging)), tagging, strlen(tagging));
  }

  if (debug) printf("Capturing PCAP string: %s\n", string);
  if ((p = thc_pcap_init(interface, string)) == NULL) {
    fprintf(stderr, "Error: could not capture on interface %s with string %s\n",
            interface, string);
    exit(-1);
  }

  if (input != NULL)
    if ((in = fopen(input, "r")) == NULL) {
      fprintf(stderr, "Error: could not open file %s\n", input);
      exit(-1);
    }

  if (output != NULL) {
    if ((out = fopen(output, "w")) == NULL) {
      fprintf(stderr, "Error: could not create output file %s\n", output);
      exit(-1);
    } else
      setvbuf(out, NULL, _IONBF,
              0);  // dont buffer output to file - for immediate scripting
  }
  // cur_enum states: 0 = as-is, 2 = dhcp, 1 = mac, 3 = from-to, 4 = ipv4
  // curr states: 0 = cmdline, 1.. = line no. in input file
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  if (verbose) {
    timeval = time(NULL);
    printf("Starting alive6 %s (c) 2020 by van Hauser / THC at %s\n", VERSION,
           ctime(&timeval));
  }
  if (renew && src6[0] > 0xfd && (multicast6 != NULL && multicast6[0] > 0xfd))
    prefer = PREFER_LINK;
  while (curr <= list) {
    ok = 1;
    local = -1;
    if (cur_enum == 0) {
      if (curr == 0) {  // the command line target first - if present
        cur_dst = multicast6;
      } else {  // input file processing, if present
        if (feof(in)) curr++;
        line[0] = 0;
        ptr = fgets(line, sizeof(line), in);
        ptr = NULL;
        line[sizeof(line) - 1] = 0;
        j = strlen(line);
        if (j > 0)
          if (line[j - 1] == '\n') {
            line[j - 1] = 0;
            j--;
          }
        if (j > 0)
          if (line[j - 1] == '\r') {
            line[j - 1] = 0;
            j--;
          }
        if (j > 0) {
          ptr = line + j - 1;
          while (*ptr == ' ' || *ptr == '\t')
            *ptr-- = 0;
          ptr = line;
          while (*ptr == ' ' || *ptr == '\t')
            ptr++;
          if (*ptr == '#') ptr = NULL;
        } else
          ok = 0;
      }
      // from here for both target input options
      if (ptr != NULL && (index(ptr, '-') != NULL && index(ptr, '.') == NULL) &&
          index(ptr, ':') != NULL) {
        fromto = 1;
        cur_enum = 3;
      } else {
        if (ok && verbose > 1) printf("Resolving %s ...\n", ptr);
        if ((cur_dst = thc_resolve6(ptr)) == NULL) {
          if (ok) {
            fprintf(stderr, "Warning: could not resolve %s, skipping\n", ptr);
          } else {
            if (index(ptr, '/') != NULL)
              fprintf(stderr,
                      "Warning: network mask is ignored and processed as "
                      "single host: %s\n",
                      ptr);
          }
          ok = 0;
        } else {
          memcpy(orig_dst, cur_dst, 16);
          local = thc_is_dst_local(interface, cur_dst);
          if (enumerate_dhcp || fcnt > 0) {
            /* if (local > 0) {
              if (cur_dst[0] != 0xff)
                if ((p2 = thc_ipv62notation(cur_dst)) != NULL) {
                  fprintf(stderr, "Warning: enumeration on local address %s
            disabled, use ff02::1!\n", p2); free(p2);
                }
            } else*/
            {
              i = 0;
              if (no_nets > 0)
                for (j = 0; j < no_nets; j++)
                  if (memcmp(nets[j], cur_dst, 8) == 0) i = 1;
              if (i == 0) {
                if (enumerate_dhcp)
                  cur_enum = 2;
                else
                  cur_enum = 4;
                restart = 1;
                if (no_nets < MAX_NETS) {
                  memcpy(nets[no_nets], cur_dst, 8);
                  no_nets++;
                  if (no_nets == MAX_NETS)
                    fprintf(stderr,
                            "Warning: more than %d networks found, disabling "
                            "double network check!\n",
                            MAX_VENDID);
                }
              } else {
                ok = -1;  // already scanned
              }
            }
          } else if (enumerate_mac && cur_dst[11] == 0xff &&
                     cur_dst[12] == 0xfe) {
            i = 0;
            if (no_vendid > 0)
              for (j = 0; j < no_vendid; j++)
                if (memcmp(vendid[j], cur_dst, 11) == 0) i = 1;
            if (i == 0) {
              cur_enum = 1;
              restart = 1;
            } else
              ok = -1;  // already scanned
          } else if (fcnt) {
            cur_enum = 4;
            restart = 1;
          }
        }
      }
      if (cur_enum == 0 && curr == 0) curr++;
    } else if (cur_enum == 1) {
      // enumeration of vendor-id keyspaces identified, lowest 3 bytes of ipv6
      if (restart) {
        restart = 0;
        bl = bm = bh = 0;
        memcpy(cur_dst, orig_dst, 16);
        memset(cur_dst + 13, 0, 3);
        if (verbose) {
          p2 = thc_ipv62notation(cur_dst);
          printf("Info: started autoconfiguration address space scan on %s\n",
                 p2);
          free(p2);
        }
        if (no_vendid < MAX_VENDID) {
          memcpy(vendid[no_vendid], cur_dst, 11);
          no_vendid++;
          if (no_vendid == MAX_VENDID)
            fprintf(stderr,
                    "Warning: more than %d vendor ids found, disabling double "
                    "vendor id check!\n",
                    MAX_VENDID);
        }
      } else {
        if (bl == 255) {
          bl = 0;
          if (bm == 255) {
            bm = 0;
            bh++;
            cur_dst[13] = bh;
          } else {
            bm++;
          }
          cur_dst[14] = bm;
        } else {
          bl++;
          if (bh == 255 && bm == 255 && bl == 255) {
            if (fcnt) {
              cur_enum = 4;
              restart = 1;
            } else {
              cur_enum = 0;
              if (curr == 0) curr++;
            }
          }
        }
      }
      cur_dst[15] = bl;
    } else if (cur_enum == 2) {
      // enumeration of common dhcp6 address space,
      // using dict[] ranges, approx. 2200 addresses
      if (restart) {
        memcpy(cur_dst, orig_dst, 16);
        memset(cur_dst + 8, 0, 8);
        if (verbose) {
          p2 = thc_ipv62notation(cur_dst);
          printf("Info: started common address space scan on %s\n", p2);
          free(p2);
        }
        restart = 0;
        ip1 = ip2 = ip3 = ip4 = 0;  // only because dict starts with 0
        dictptr = 0;
      } else {
        if (ip4 < dict[dictptr + 7])
          ip4++;
        else if (ip3 < dict[dictptr + 6]) {
          ip3++;
          ip4 = dict[dictptr + 3];
        } else if (ip2 < dict[dictptr + 5]) {
          ip2++;
          ip3 = dict[dictptr + 2];
          ip4 = dict[dictptr + 3];
        } else if (ip1 < dict[dictptr + 4]) {
          ip1++;
          ip2 = dict[dictptr + 1];
          ip3 = dict[dictptr + 2];
          ip4 = dict[dictptr + 3];
        } else {
          dictptr += 8;
          ip1 = dict[dictptr];
          ip2 = dict[dictptr + 1];
          ip3 = dict[dictptr + 2];
          ip4 = dict[dictptr + 3];
        }
        cur_dst[8] = ip1 / 256;
        cur_dst[9] = ip1 % 256;
        cur_dst[10] = ip2 / 256;
        cur_dst[11] = ip2 % 256;
        cur_dst[12] = ip3 / 256;
        cur_dst[13] = ip3 % 256;
        cur_dst[14] = ip4 / 256;
        cur_dst[15] = ip4 % 256;

        if (ip1 == ip2 && ip1 == ip3 && ip1 == ip4 &&
            ip1 == 0xffff) {  // end of dict
          if (enumerate_mac && orig_dst[11] == 0xff && orig_dst[12] == 0xfe) {
            i = 0;
            if (no_vendid > 0)
              for (j = 0; j < no_vendid; j++)
                if (memcmp(vendid[j], orig_dst, 11) == 0) i = 1;
            if (i == 0) {
              cur_enum = 1;
              restart = 1;
            } else
              cur_enum = 0;
          } else {
            if (fcnt) {
              cur_enum = 4;
              restart = 1;
            } else {
              cur_enum = 0;
            }
          }
          if (curr == 0 && cur_enum == 0) curr++;
        }
      }
    } else if (cur_enum == 4) {  // -4 option

      if (restart) {  // bl = return, bm = fcnt_counter, bh = state
        if (verbose) {
          p2 = thc_ipv62notation(cur_dst);
          printf("Info: started IPv4 address space scan on %s\n", p2);
          free(p2);
        }
        restart = 0;
        bl = bm = bh = 0;
        addr_cur = four_from[bm];
      }
      memcpy(cur_dst, orig_dst, 16);
      bl = adress4to6(cur_dst, addr_cur, &bh);
      // printf("return %d, state now %d, fcnt is %d\n", bl, bh, bm);
      if (bl == 1) {  // done addr_cur state
        addr_cur++;
        bh = 0;
        if (addr_cur > four_to[bm]) {
          bm++;
          if (bm < fcnt) {
            addr_cur = four_from[bm];
          } else {
            cur_enum = 0;
            if (curr == 0) curr++;
          }
        }
      }
    }  //    else

    if (cur_enum == 3) {
      if (fromto) {
        fromto = 0;
        ok = 1;
        // init
        if (strlen(ptr) > 80) {
          ok = 0;
        } else {
          if (curr != 0) {
            memcpy(line2, line, 80);
            ptr = line2;
            line2[80] = 0;
          }
          memset(line, 0, 80);
          i = j = k = 0;
          while (i == 0) {
            while (ptr[k] != '-' && k < 80 && ptr[k] != 0)
              line[j++] = ptr[k++];
            if (ptr[k] == '-')
              while (ptr[k] != ':' && k < 80 && ptr[k] != 0)
                k++;
            if (ptr[k] != ':') i = 1;
          }
          if (verbose > 1) printf("Resolving %s ...\n", line);
          // printf("ptr: %s, line %s, cur_dst %s, multicast6 %s\n", ptr, line,
          // cur_dst, multicast6);
          if ((cur_dst = thc_resolve6(line)) == NULL) {
            ok = 0;
          } else {
            memset(line, 0, 80);
            j = k = strlen(ptr) - 1;
            while (i == 1) {
              while (ptr[k] != '-' && k >= 0 && ptr[k] != 0)
                line[j--] = ptr[k--];
              if (ptr[k] == '-')
                while (ptr[k] != ':' && k >= 0 && ptr[k] != 0)
                  k--;
              if (ptr[k] != ':') i = 0;
            }
          }
          ptr2 = &line[j + 1];
          if (verbose > 1) printf("Resolving %s ...\n", ptr2);
          if ((ptr3 = thc_resolve6(ptr2)) == NULL) {
            ok = 0;
          } else {
            cip1 = fip1 = (cur_dst[0] << 8) + (unsigned char)cur_dst[1];
            cip2 = fip2 = (cur_dst[2] << 8) + (unsigned char)cur_dst[3];
            cip3 = fip3 = (cur_dst[4] << 8) + (unsigned char)cur_dst[5];
            cip4 = fip4 = (cur_dst[6] << 8) + (unsigned char)cur_dst[7];
            cip5 = fip5 = (cur_dst[8] << 8) + (unsigned char)cur_dst[9];
            cip6 = fip6 = (cur_dst[10] << 8) + (unsigned char)cur_dst[11];
            cip7 = fip7 = (cur_dst[12] << 8) + (unsigned char)cur_dst[13];
            cip8 = fip8 = (cur_dst[14] << 8) + (unsigned char)cur_dst[15];
            tip1 = (ptr3[0] << 8) + (unsigned char)ptr3[1];
            tip2 = (ptr3[2] << 8) + (unsigned char)ptr3[3];
            tip3 = (ptr3[4] << 8) + (unsigned char)ptr3[5];
            tip4 = (ptr3[6] << 8) + (unsigned char)ptr3[7];
            tip5 = (ptr3[8] << 8) + (unsigned char)ptr3[9];
            tip6 = (ptr3[10] << 8) + (unsigned char)ptr3[11];
            tip7 = (ptr3[12] << 8) + (unsigned char)ptr3[13];
            tip8 = (ptr3[14] << 8) + (unsigned char)ptr3[15];
            if (fip1 > tip1 || fip2 > tip2 || fip3 > tip3 || fip4 > tip4 ||
                fip5 > tip5 || fip6 > tip6 || fip7 > tip7 || fip8 > tip8)
              ok = 0;
            if (ok && verbose) {
              p2 = thc_ipv62notation(cur_dst);
              p3 = thc_ipv62notation(ptr3);
              printf("Info: started range address scan from %s to %s \n", p2,
                     p3);
              free(p2);
              free(p3);
            }
            free(ptr3);
          }
        }
        if (ok) {
          memcpy(orig_dst, cur_dst, 16);
        } else {
          fprintf(stderr, "Error: range is invalid: %s, skipping\n", ptr);
          cur_enum = 0;
          if (curr == 0) curr++;
        }
      } else {
        inc_step = 1;
        inc_next = 0;
        // printf("%d S: %04x-%04x=%04x %04x-%04x=%04x %04x-%04x=%04x
        // %04x-%04x=%04x %04x-%04x=%04x %04x-%04x=%04x %04x-%04x=%04x
        // %04x-%04x=%04x\n", ok, fip1, tip1, cip1, fip2, tip2, cip2, fip3, tip3,
        // cip3, fip4, tip4, cip4, fip5, tip5, cip5, fip6, tip6, cip6, fip7,
        // tip7, cip7, fip8, tip8, cip8);
        if (fip8 != tip8 && (inc_step || inc_next)) {
          if (inc_step) {
            inc_step = 0;
            if (cip8 + step <= tip8) {
              cip8 += step;
            } else {
              cip8 = fip8 + (step + cip8 - tip8);
              if (step != 256) cip8--;
              inc_next = 1;
            }
          } else {
            if (cip8 < tip8) {
              cip8++;
              inc_next = 0;
            } else {
              cip8 = fip8;
            }
          }
        }
        if (fip7 != tip7 && (inc_step || inc_next)) {
          if (inc_step) {
            inc_step = 0;
            if (cip7 + step <= tip7) {
              cip7 += step;
            } else {
              cip7 = fip7 + (step + cip7 - tip7);
              if (step != 256) cip7--;
              inc_next = 1;
            }
          } else {
            if (cip7 < tip7) {
              cip7++;
              inc_next = 0;
            } else {
              cip7 = fip7;
            }
          }
        }
        if (fip6 != tip6 && (inc_step || inc_next)) {
          if (inc_step) {
            inc_step = 0;
            if (cip6 + step <= tip6) {
              cip6 += step;
            } else {
              cip6 = fip6 + (step + cip6 - tip6);
              if (step != 256) cip6--;
              inc_next = 1;
            }
          } else {
            if (cip6 < tip6) {
              cip6++;
              inc_next = 0;
            } else {
              cip6 = fip6;
            }
          }
        }
        if (fip5 != tip5 && (inc_step || inc_next)) {
          if (inc_step) {
            inc_step = 0;
            if (cip5 + step <= tip5) {
              cip5 += step;
            } else {
              cip5 = fip5 + (step + cip5 - tip5);
              if (step != 256) cip5--;
              inc_next = 1;
            }
          } else {
            if (cip5 < tip5) {
              cip5++;
              inc_next = 0;
            } else {
              cip5 = fip5;
            }
          }
        }
        if (fip4 != tip4 && (inc_step || inc_next)) {
          if (inc_step) {
            inc_step = 0;
            if (cip4 + step <= tip4) {
              cip4 += step;
            } else {
              cip4 = fip4 + (step + cip4 - tip4);
              if (step != 256) cip4--;
              inc_next = 1;
            }
          } else {
            if (cip4 < tip4) {
              cip4++;
              inc_next = 0;
            } else {
              cip4 = fip4;
            }
          }
        }
        if (fip3 != tip3 && (inc_step || inc_next)) {
          if (inc_step) {
            inc_step = 0;
            if (cip3 + step <= tip3) {
              cip3 += step;
            } else {
              cip3 = fip3 + (step + cip3 - tip3);
              if (step != 256) cip3--;
              inc_next = 1;
            }
          } else {
            if (cip3 < tip3) {
              cip3++;
              inc_next = 0;
            } else {
              cip3 = fip3;
            }
          }
        }
        if (fip2 != tip2 && (inc_step || inc_next)) {
          if (inc_step) {
            inc_step = 0;
            if (cip2 + step <= tip2) {
              cip2 += step;
            } else {
              cip2 = fip2 + (step + cip2 - tip2);
              if (step != 256) cip2--;
              inc_next = 1;
            }
          } else {
            if (cip2 < tip2) {
              cip2++;
              inc_next = 0;
            } else {
              cip2 = fip2;
            }
          }
        }
        if (fip1 != tip1 && (inc_step || inc_next)) {
          if (inc_step) {
            inc_step = 0;
            if (cip1 + step <= tip1) {
              cip1 += step;
            } else {
              cip1 = fip1 + (step + cip1 - tip1);
              if (step != 256) cip1--;
              inc_next = 1;
            }
          } else {
            if (cip1 < tip1) {
              cip1++;
              inc_next = 0;
            } else {
              cip1 = fip1;
            }
          }
        }

        if (inc_step || inc_next)  // we are done
          ok = 0;
        // printf("%d E: %04x-%04x=%04x %04x-%04x=%04x %04x-%04x=%04x
        // %04x-%04x=%04x %04x-%04x=%04x %04x-%04x=%04x %04x-%04x=%04x
        // %04x-%04x=%04x\n", ok, fip1, tip1, cip1, fip2, tip2, cip2, fip3, tip3,
        // cip3, fip4, tip4, cip4, fip5, tip5, cip5, fip6, tip6, cip6, fip7,
        // tip7, cip7, fip8, tip8, cip8);

        cur_dst[0] = cip1 / 256;
        cur_dst[1] = cip1 % 256;
        cur_dst[2] = cip2 / 256;
        cur_dst[3] = cip2 % 256;
        cur_dst[4] = cip3 / 256;
        cur_dst[5] = cip3 % 256;
        cur_dst[6] = cip4 / 256;
        cur_dst[7] = cip4 % 256;
        cur_dst[8] = cip5 / 256;
        cur_dst[9] = cip5 % 256;
        cur_dst[10] = cip6 / 256;
        cur_dst[11] = cip6 % 256;
        cur_dst[12] = cip7 / 256;
        cur_dst[13] = cip7 % 256;
        cur_dst[14] = cip8 / 256;
        cur_dst[15] = cip8 % 256;

        if (ok == 0) {
          cur_enum = 0;
          if (enumerate_dhcp) {
            /* if (local) {
              if (cur_dst[0] != 0xff) {
                p2 = thc_ipv62notation(orig_dst);
                fprintf(stderr, "Warning: enumeration on local address %s
            disabled, use ff02::1!\n", p2); free(p2);
              }
            } else */
            {
              i = 0;
              if (no_nets > 0)
                for (j = 0; j < no_nets; j++)
                  if (memcmp(nets[j], cur_dst, 8) == 0) i = 1;
              if (i == 0) {
                cur_enum = 2;
                restart = 1;
                if (no_nets < MAX_NETS) {
                  memcpy(nets[no_nets], cur_dst, 8);
                  no_nets++;
                  if (no_nets == MAX_NETS)
                    fprintf(stderr,
                            "Warning: more than %d networks found, disabling "
                            "double network check!\n",
                            MAX_VENDID);
                }
              } else {
                ok = -1;  // already scanned
              }
            }
          } else if (enumerate_mac && orig_dst[11] == 0xff &&
                     orig_dst[12] == 0xfe) {
            i = 0;
            if (no_vendid > 0)
              for (j = 0; j < no_vendid; j++)
                if (memcmp(vendid[j], cur_dst, 11) == 0) i = 1;
            if (i == 0) {
              cur_enum = 1;
              restart = 1;
            }
          } else {
            cur_enum = 0;
          }
          if (curr == 0) curr++;
        }
      }
    }
    if (cur_enum > 4) {
      fprintf(stderr, "Error: WTF?!\n");
      exit(-1);
    }
    if (print_only && ok) {
      p2 = thc_ipv62notation(cur_dst);
      printf("Address: %s\n", p2);
      free(p2);
      ok = 0;
    }
    // here we send the alive check packets - if we have a valid destination
    if (do_router) {
      routers[0] = cur_dst;
      routers[1] = NULL;
      cur_dst = router6;  // switch destination and router
    }
    // central dst mac lookup and fast/slow implementation
    no_send = no_send_local;
    if (ok != 0 && cur_dst != NULL && do_router == 0 && use_dmac == 0) {
      if (local == -1) local = thc_is_dst_local(interface, cur_dst);
      if (local == 0 && slow == 0) {
        if (rmac == NULL) rmac = thc_get_mac(interface, src6, cur_dst);
        mac = rmac;
      }
      if (local && (ndp_only || slow))
        mac = thc_lookup_ipv6_mac(interface, cur_dst);
      else
        mac = thc_get_mac(interface, src6, cur_dst);

      if (local && mac != NULL && slow == 0 && cur_dst[0] != 0xff) {
        // if a local system has an neighbor entry, assume its alive if the slow
        // mode is not set. so if proxy NA is present, use -S
        if (resolve) he = gethostbyaddr(cur_dst, 16, AF_INET6);
        p2 = thc_ipv62notation(cur_dst);
        printf("Alive: %s%s%s%s [NDP %02x:%02x:%02x:%02x:%02x:%02x]\n", p2,
               resolve ? " (" : "", resolve && he != NULL ? he->h_name : "",
               resolve ? ")" : "", mac[0], mac[1], mac[2], mac[3], mac[4],
               mac[5]);
        if (out != NULL)
          fprintf(out, "%s%s%s%s\n", p2, resolve ? " (" : "",
                  (resolve && he != NULL) ? he->h_name : "",
                  resolve ? ")" : "");
        free(p2);
        if (alive_no < MAX_ALIVE && (alive[alive_no] = malloc(16)) != NULL) {
          memcpy(alive[alive_no], cur_dst, 16);
          alive_no++;
          if (alive_no == MAX_ALIVE)
            fprintf(stderr,
                    "Warning: more than %d alive systems detected, disabling "
                    "double results check!\n",
                    MAX_ALIVE);
        }
        tcount++;
        ok = 0;
      } else if (ndp_only)
        ok = 0;
      if (mac == NULL) {
        p2 = thc_ipv62notation(cur_dst);
        if (ndp_only == 0)
          fprintf(stderr, "Error: Can not resolve mac address for %s\n", p2);
        free(p2);
        ok = 0;
      }
    }
    if (use_dmac)
      mac = dmac;
    else if (local == 0)
      no_send = no_send_remote;

    if (ok != 0 && cur_dst != NULL) {
      if (renew) {
        while ((src6 = thc_get_own_ipv6(interface, cur_dst, prefer)) == NULL ||
               (prefer == PREFER_GLOBAL && src6[0] > 0xfd)) {
          fprintf(stderr,
                  "Error: no global IPv6 address found for interface %s, "
                  "sleeping for 60 seconds and waiting for one! Next check in "
                  "60 seconds ...\n",
                  interface);
          sleep(60);
        }
      }
      if (debug)
        printf("DEBUG: sending alive check packets to %s\n",
               thc_ipv62notation(cur_dst));
      else if (verbose > 2) {
        p2 = thc_ipv62notation(cur_dst);
        printf("Testing %s ...\n", p2);
        free(p2);
      }
      for (nos = 0; nos < no_send;
           nos++) {  // send -n defined times, default: 1
        if (rand_source) {
          for (i = rand_source; i < 16; i++)
            src6[i] = rand() % 256;
        }
        if (synports[0] != -1 || portscan) {
          i = 0;
          while ((portscan > 0 && portscan < 65536) ||
                 (synports[i] != -1 && i < MAX_PORTS)) {
            if (portscan > 0)
              if (rand_source) {
                for (i = rand_source; i < 16; i++)
                  src6[i] = rand() % 256;
              }
            if ((pkt =
                     thc_create_ipv6_extended(interface, prefer, &pkt_len, src6,
                                              cur_dst, 0, 0, 0, 0, 0)) == NULL)
              return -1;
            if (router6 != NULL)
              if (thc_add_hdr_route(pkt, &pkt_len, routers, 1) < 0) return -1;
            if (portscan) {
              if (thc_add_tcp(pkt, &pkt_len, sp, portscan % 65536,
                              (sp << 16) + sp, 0, TCP_SYN, 5760, 0, NULL, 0,
                              NULL, 0) < 0)
                return -1;
              portscan++;
            } else {
              if (thc_add_tcp(pkt, &pkt_len, sp, synports[i] % 65536,
                              (sp << 16) + sp, 0, TCP_SYN, 5760, 0, tcp_opt,
                              TCP_OPT_LEN, NULL, 0) < 0)
                return -1;
            }
            if (thc_generate_pkt(interface, smac, mac, pkt, &pkt_len) < 0) {
              fprintf(stderr, "Error: Can not send packet, exiting ...\n");
              exit(-1);
            }
            if (router6 != NULL) {
              hdr = (thc_ipv6_hdr *)pkt;
              thc_send_as_fragment6(
                  interface, src6, cur_dst, NXT_ROUTE, hdr->pkt + 40 + offset,
                  hdr->pkt_len - 40 - offset,
                  hdr->pkt_len > 1240
                      ? 1240
                      : (((hdr->pkt_len - 40 - offset) / 16) + 1) * 8);
            } else
              errcnt = 0;
            while (thc_send_pkt(interface, pkt, &pkt_len) < 0) {
              usleep(1);
              if (errcnt > 0)
                usleep(errcnt << 10);
              else if (errcnt > 10) {
                printf(
                    "Error: unable to send packet to network, waiting for 60 "
                    "seconds to recover ...\n");
                sleep(60);
                errcnt = 0;
              }
              errcnt++;
            }
            pkt = thc_destroy_packet(pkt);
            if (waittime) usleep(waittime);
            i++;
            while (thc_pcap_check(p, (char *)check_packets, NULL) > 0)
              ;
          }
          if (portscan) portscan = 1;
        }
        if (do_ping) {
          if ((pkt = thc_create_ipv6_extended(interface, prefer, &pkt_len, src6,
                                              cur_dst, 0, 0, 0, 0, 0)) == NULL)
            return -1;
          if (router6 != NULL)
            if (thc_add_hdr_route(pkt, &pkt_len, routers, 1) < 0) return -1;
          if (thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, 0xfacebabe,
                            (unsigned char *)&buf, sizeof(buf), 0) < 0)
            return -1;
          if (thc_generate_pkt(interface, smac, mac, pkt, &pkt_len) < 0) {
            fprintf(stderr, "Error: Can not send packet, exiting ...\n");
            exit(-1);
          }
          if (router6 != NULL) {
            hdr = (thc_ipv6_hdr *)pkt;
            thc_send_as_fragment6(
                interface, src6, cur_dst, NXT_ROUTE, hdr->pkt + 40 + offset,
                hdr->pkt_len - 40 - offset,
                hdr->pkt_len > 1240
                    ? 1240
                    : (((hdr->pkt_len - 40 - offset) / 16) + 1) * 8);
          } else
            while (thc_send_pkt(interface, pkt, &pkt_len) < 0)
              usleep(1);
          pkt = thc_destroy_packet(pkt);
          if (waittime) usleep(waittime);
        }
        if (do_dst) {
          if ((pkt = thc_create_ipv6_extended(interface, prefer, &pkt_len, src6,
                                              cur_dst, 0, 0, 0, 0, 0)) == NULL)
            return -1;
          if (router6 != NULL)
            if (thc_add_hdr_route(pkt, &pkt_len, routers, 1) < 0) return -1;
          if (thc_add_hdr_dst(pkt, &pkt_len, (unsigned char *)&buf2,
                              sizeof(buf2)) < 0)
            return -1;
          if (thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, 0xfacebabe,
                            (unsigned char *)&buf, sizeof(buf), 0) < 0)
            return -1;
          thc_generate_pkt(interface, smac, mac, pkt, &pkt_len);
          if (router6 != NULL) {
            hdr = (thc_ipv6_hdr *)pkt;
            thc_send_as_fragment6(
                interface, src6, cur_dst, NXT_ROUTE, hdr->pkt + 40 + offset,
                hdr->pkt_len - 40 - offset,
                hdr->pkt_len > 1240
                    ? 1240
                    : (((hdr->pkt_len - 40 - offset) / 16) + 1) * 8);
          } else
            while (thc_send_pkt(interface, pkt, &pkt_len) < 0)
              usleep(1);
          pkt = thc_destroy_packet(pkt);
          if (waittime) usleep(waittime);
        }
        if (do_hop) {
          if ((pkt = thc_create_ipv6_extended(interface, prefer, &pkt_len, src6,
                                              cur_dst, 0, 0, 0, 0, 0)) == NULL)
            return -1;
          if (router6 != NULL)
            if (thc_add_hdr_route(pkt, &pkt_len, routers, 1) < 0) return -1;
          if (thc_add_hdr_hopbyhop(pkt, &pkt_len, (unsigned char *)&buf2,
                                   sizeof(buf2)) < 0)
            return -1;
          if (thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, 0xfacebabe,
                            (unsigned char *)&buf, sizeof(buf), 0) < 0)
            return -1;
          thc_generate_pkt(interface, smac, mac, pkt, &pkt_len);
          if (router6 != NULL) {
            hdr = (thc_ipv6_hdr *)pkt;
            thc_send_as_fragment6(
                interface, src6, cur_dst, NXT_ROUTE, hdr->pkt + 40 + offset,
                hdr->pkt_len - 40 - offset,
                hdr->pkt_len > 1240
                    ? 1240
                    : (((hdr->pkt_len - 40 - offset) / 16) + 1) * 8);
          } else
            while (thc_send_pkt(interface, pkt, &pkt_len) < 0)
              usleep(1);
          pkt = thc_destroy_packet(pkt);
          if (waittime) usleep(waittime);
        }
        if (udpports[0] != -1) {
          i = 0;
          while (udpports[i] != -1 && i < MAX_PORTS) {
            if ((pkt =
                     thc_create_ipv6_extended(interface, prefer, &pkt_len, src6,
                                              cur_dst, 0, 0, 0, 0, 0)) == NULL)
              return -1;
            if (router6 != NULL)
              if (thc_add_hdr_route(pkt, &pkt_len, routers, 1) < 0) return -1;
            if (thc_add_udp(pkt, &pkt_len, sp, udpports[i] % 65536, 0, dns6buf,
                            sizeof(dns6buf)) < 0)
              return -1;
            if (thc_generate_pkt(interface, smac, mac, pkt, &pkt_len) < 0) {
              fprintf(stderr, "Error: Can not send packet, exiting ...\n");
              exit(-1);
            }
            if (router6 != NULL) {
              hdr = (thc_ipv6_hdr *)pkt;
              thc_send_as_fragment6(
                  interface, src6, cur_dst, NXT_ROUTE, hdr->pkt + 40 + offset,
                  hdr->pkt_len - 40 - offset,
                  hdr->pkt_len > 1240
                      ? 1240
                      : (((hdr->pkt_len - 40 - offset) / 16) + 1) * 8);
            } else
              while (thc_send_pkt(interface, pkt, &pkt_len) < 0)
                usleep(1);
            pkt = thc_destroy_packet(pkt);
            if (waittime) usleep(waittime);
            i++;
          }
        }
        if (ackports[0] != -1) {
          i = 0;
          while (ackports[i] != -1 && i < MAX_PORTS) {
            if ((pkt =
                     thc_create_ipv6_extended(interface, prefer, &pkt_len, src6,
                                              cur_dst, 0, 0, 0, 0, 0)) == NULL)
              return -1;
            if (router6 != NULL)
              if (thc_add_hdr_route(pkt, &pkt_len, routers, 1) < 0) return -1;
            if (thc_add_tcp(pkt, &pkt_len, sp, ackports[i] % 65536,
                            (sp << 16) + sp, (sp << 16) + sp, TCP_ACK, 5760, 0,
                            NULL, 0, NULL, 0) < 0)
              return -1;
            if (thc_generate_pkt(interface, smac, mac, pkt, &pkt_len) < 0) {
              fprintf(stderr, "Error: Can not send packet, exiting ...\n");
              exit(-1);
            }
            if (router6 != NULL) {
              hdr = (thc_ipv6_hdr *)pkt;
              thc_send_as_fragment6(
                  interface, src6, cur_dst, NXT_ROUTE, hdr->pkt + 40 + offset,
                  hdr->pkt_len - 40 - offset,
                  hdr->pkt_len > 1240
                      ? 1240
                      : (((hdr->pkt_len - 40 - offset) / 16) + 1) * 8);
            } else
              while (thc_send_pkt(interface, pkt, &pkt_len) < 0)
                usleep(1);
            pkt = thc_destroy_packet(pkt);
            if (waittime) usleep(waittime);
            i++;
          }
        }
      }

      if (ok == -1) {
        ok = 0;
        //        if (cur_enum != 3)
        cur_enum = 0;
      }

      tcount++;
      if (do_router) cur_dst = router6;  // switch back

      // cleanup
      if (cur_enum == 0 && cur_dst != multicast6) free(cur_dst);

      if (cur_enum == 0 || cur_dst[15] == 0xff || tcount % 16 == 0)
        while (thc_pcap_check(p, (char *)check_packets, NULL) > 0)
          ;
    }
    if (mac != NULL && mac != rmac && use_dmac == 0) {
      free(mac);
      mac = NULL;
    }
  }

  //  sleep(1);
  while (thc_pcap_check(p, (char *)check_packets, NULL) > 0)
    ;
  if (curr > 1 || list > 0 || ok != 0 || tcount > alive_no ||
      still_not_there == 1) {
    passed = time(NULL);
    do {
      thc_pcap_check(p, (char *)check_packets, NULL);
    } while (passed + 5 >= time(NULL) &&
             (verbose > 1 ||
              (tcount >= alive_no && (tcount > 1 || list > 0 || alive_no == 0 ||
                                      still_not_there == 1)) ||
              (multicast6 != NULL && multicast6[0] == 0xff)));
  }
  while (thc_pcap_check(p, (char *)check_packets, NULL) > 0)
    ;
  thc_pcap_close(p);
  if (out != NULL) fclose(out);
  printf("\nScanned %lu address%s and found %d system%s alive\n", tcount,
         tcount == 1 ? "" : "es", alive_no, alive_no == 1 ? "" : "s");
  if (verbose) {
    timeval = time(NULL);
    printf("Completed alive6 scan at %s\n", ctime(&timeval));
  }
  if (alive_no)
    return 0;
  else
    return 1;
}
