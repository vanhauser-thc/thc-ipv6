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

/*
 * Fuzzing data types:
 *  F = flags = 1 byte = 8 bits | flags | 8 ; 256
 *  B = byte = 1 byte | 0 1 254 255 xor XOR | 6 ; 256
 *  X = byte = 1 byte | all values from 0 to 255
 *  W = word = 2 bytes | 0,1,254,255^2 xor XOR | 18 ; 65536
 *  D = double word = 4 bytes | {0,1,254,255}^4 xor XOR | 258 ; 4294967295
 *  . = byte = ignore, jump over
 */

char fuzztype_ether[] = "..............";
char fuzztype_ip6[] = "XF..WXBXX..............XX..............";
char fuzztype_ip6no[] = "........................................";
char fuzztype_icmp6[] = "XX..";
char fuzztype_icmp6no[] = "....";
char fuzztype_icmp6ping[] = "";
char fuzztype_icmp6ra[] =
    "........XXWWWXXXX........XX.............XXXX....XXXXXBB..XX............."
    "XXXBB....XX.............XXXBB....X...X....XX.....X......XXXXXXXXX";
char fuzztype_icmp6ns[] = "XX..XX............XXXX";
char fuzztype_icmp6na[] = "FFFFXX............XXXX";
char fuzztype_icmp6nq[] = "FXFX........XX............XX";
char fuzztype_icmp6mld[] = "WWXXXX............XX";
char fuzztype_icmp6mld2rep[] =
    "WFFXFFF................................................XFFF..............."
    ".................................XFFF....................................."
    "...........";
char fuzztype_icmp6mld2que[] = "WWXXXX............XXFWFF";
char fuzztype_tcp[] = "WWWWWWXXWWWXXWXXXXXXWWWWXX";
char fuzztype_pim_hello[] =
    "X....X.X..WW...BXXXX.....X.XX....X.XXXBB.............B";
char fuzztype_pim_bootstrap[] =
    "X...XX..................XXXXX...............XXXXXX................XX";
char fuzztype_pim_assert[] =
    "X...XXXXX...............XX.X.............XX.......";

unsigned char      flags[] = {0, 1, 2, 4, 8, 16, 32, 64, 128, 254, 255};  // 11
unsigned char      bytes[] = {0, 1, 254, 255};                            // 4
unsigned short int words[] = {0x0000, 0x0001, 0x00fe, 0x00ff, 0x0100, 0x0101,
                              0x01fe, 0x01ff, 0xfe00, 0xfe01, 0xfefe, 0xfeff,
                              0xff00, 0xff01, 0xfffe, 0xffff};  // 16
unsigned int       xors[] = {0, 0xffffffff};                    // 2
unsigned char      extends[] = {
    0,   1,   2,   3,   4,   5,   6,   7,   8,   9,   10,  11,  12,  13,  14,
    15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  25,  26,  27,  28,  29,
    30,  31,  32,  33,  34,  35,  36,  37,  38,  39,  40,  41,  42,  43,  44,
    45,  46,  47,  48,  49,  50,  51,  52,  53,  54,  55,  56,  57,  58,  59,
    60,  61,  62,  63,  64,  65,  66,  67,  68,  69,  70,  71,  72,  73,  74,
    75,  76,  77,  78,  79,  80,  81,  82,  83,  84,  85,  86,  87,  88,  89,
    90,  91,  92,  93,  94,  95,  96,  97,  98,  99,  100, 101, 102, 103, 104,
    105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119,
    120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134,
    135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149,
    150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164,
    165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179,
    180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194,
    195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209,
    210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224,
    225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239,
    240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254,
    255};  // 256
unsigned int dwords[] = {
    0x00000000, 0x00000001, 0x000000fe, 0x000000ff, 0x00000100, 0x00000101,
    0x000001fe, 0x000001ff, 0x0000fe00, 0x0000fe01, 0x0000fefe, 0x0000feff,
    0x0000ff00, 0x0000ff01, 0x0000fffe, 0x0000ffff, 0x00010000, 0x00010001,
    0x000100fe, 0x000100ff, 0x00010100, 0x00010101, 0x000101fe, 0x000101ff,
    0x0001fe00, 0x0001fe01, 0x0001fefe, 0x0001feff, 0x0001ff00, 0x0001ff01,
    0x0001fffe, 0x0001ffff, 0x00fe0000, 0x00fe0001, 0x00fe00fe, 0x00fe00ff,
    0x00fe0100, 0x00fe0101, 0x00fe01fe, 0x00fe01ff, 0x00fefe00, 0x00fefe01,
    0x00fefefe, 0x00fefeff, 0x00feff00, 0x00feff01, 0x00fefffe, 0x00feffff,
    0x00ff0000, 0x00ff0001, 0x00ff00fe, 0x00ff00ff, 0x00ff0100, 0x00ff0101,
    0x00ff01fe, 0x00ff01ff, 0x00fffe00, 0x00fffe01, 0x00fffefe, 0x00fffeff,
    0x00ffff00, 0x00ffff01, 0x00fffffe, 0x00ffffff, 0x01000000, 0x01000001,
    0x010000fe, 0x010000ff, 0x01000100, 0x01000101, 0x010001fe, 0x010001ff,
    0x0100fe00, 0x0100fe01, 0x0100fefe, 0x0100feff, 0x0100ff00, 0x0100ff01,
    0x0100fffe, 0x0100ffff, 0x01010000, 0x01010001, 0x010100fe, 0x010100ff,
    0x01010100, 0x01010101, 0x010101fe, 0x010101ff, 0x0101fe00, 0x0101fe01,
    0x0101fefe, 0x0101feff, 0x0101ff00, 0x0101ff01, 0x0101fffe, 0x0101ffff,
    0x01fe0000, 0x01fe0001, 0x01fe00fe, 0x01fe00ff, 0x01fe0100, 0x01fe0101,
    0x01fe01fe, 0x01fe01ff, 0x01fefe00, 0x01fefe01, 0x01fefefe, 0x01fefeff,
    0x01feff00, 0x01feff01, 0x01fefffe, 0x01feffff, 0x01ff0000, 0x01ff0001,
    0x01ff00fe, 0x01ff00ff, 0x01ff0100, 0x01ff0101, 0x01ff01fe, 0x01ff01ff,
    0x01fffe00, 0x01fffe01, 0x01fffefe, 0x01fffeff, 0x01ffff00, 0x01ffff01,
    0x01fffffe, 0x01ffffff, 0xfe000000, 0xfe000001, 0xfe0000fe, 0xfe0000ff,
    0xfe000100, 0xfe000101, 0xfe0001fe, 0xfe0001ff, 0xfe00fe00, 0xfe00fe01,
    0xfe00fefe, 0xfe00feff, 0xfe00ff00, 0xfe00ff01, 0xfe00fffe, 0xfe00ffff,
    0xfe010000, 0xfe010001, 0xfe0100fe, 0xfe0100ff, 0xfe010100, 0xfe010101,
    0xfe0101fe, 0xfe0101ff, 0xfe01fe00, 0xfe01fe01, 0xfe01fefe, 0xfe01feff,
    0xfe01ff00, 0xfe01ff01, 0xfe01fffe, 0xfe01ffff, 0xfefe0000, 0xfefe0001,
    0xfefe00fe, 0xfefe00ff, 0xfefe0100, 0xfefe0101, 0xfefe01fe, 0xfefe01ff,
    0xfefefe00, 0xfefefe01, 0xfefefefe, 0xfefefeff, 0xfefeff00, 0xfefeff01,
    0xfefefffe, 0xfefeffff, 0xfeff0000, 0xfeff0001, 0xfeff00fe, 0xfeff00ff,
    0xfeff0100, 0xfeff0101, 0xfeff01fe, 0xfeff01ff, 0xfefffe00, 0xfefffe01,
    0xfefffefe, 0xfefffeff, 0xfeffff00, 0xfeffff01, 0xfefffffe, 0xfeffffff,
    0xff000000, 0xff000001, 0xff0000fe, 0xff0000ff, 0xff000100, 0xff000101,
    0xff0001fe, 0xff0001ff, 0xff00fe00, 0xff00fe01, 0xff00fefe, 0xff00feff,
    0xff00ff00, 0xff00ff01, 0xff00fffe, 0xff00ffff, 0xff010000, 0xff010001,
    0xff0100fe, 0xff0100ff, 0xff010100, 0xff010101, 0xff0101fe, 0xff0101ff,
    0xff01fe00, 0xff01fe01, 0xff01fefe, 0xff01feff, 0xff01ff00, 0xff01ff01,
    0xff01fffe, 0xff01ffff, 0xfffe0000, 0xfffe0001, 0xfffe00fe, 0xfffe00ff,
    0xfffe0100, 0xfffe0101, 0xfffe01fe, 0xfffe01ff, 0xfffefe00, 0xfffefe01,
    0xfffefefe, 0xfffefeff, 0xfffeff00, 0xfffeff01, 0xfffefffe, 0xfffeffff,
    0xffff0000, 0xffff0001, 0xffff00fe, 0xffff00ff, 0xffff0100, 0xffff0101,
    0xffff01fe, 0xffff01ff, 0xfffffe00, 0xfffffe01, 0xfffffefe, 0xfffffeff,
    0xffffff00, 0xffffff01, 0xfffffffe, 0xffffffff};  // 256

#define arraysize(a) (sizeof(a) / sizeof(a[0]))
#define COUNT_FLAG arraysize(flags)
#define COUNT_BYTE arraysize(bytes)
#define COUNT_WORD arraysize(words)
#define COUNT_XOR arraysize(xors)
#define COUNT_EXTEND arraysize(extends)

#define NEVER 2000000000
#define TEST_MAX (NEVER - 1)

#define DO_NONE 0
#define DO_PING 1
#define DO_NEIGHSOL 2
#define DO_NEIGHADV 3
#define DO_RA 4
#define DO_NODEQUERY 5
#define DO_TCP 6
#define DO_MLD_REP 131
#define DO_MLD_DONE 132
#define DO_MLD_QUERY 130
#define DO_MLD2_QUERY 256
#define DO_MLD2_REPORT 143
#define DO_PIM_HELLO 65536
#define DO_PIM_BOOTSTRAP 65540
#define DO_PIM_ASSERT 65541

int port = -1;

void help(char *prg) {
  printf("%s %s (c) 2022 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf(
      "Syntax: %s [-x] [-t number | -T number] [-p number] [-IFSDHRJ] "
      "[-X|-1|-2|-3|-4|-5|-6|-7|-8|-9|-0 port|-P type] interface "
      "unicast-or-multicast-address [address-in-data-pkt]\n\n",
      prg);
  printf("Fuzzes an IPv6 packet with optional EHs and upper layer transport\n");
  printf("Options:\n");
  printf(" -X         do not add any ICMP/TCP header (transport layer)\n");
  printf(" -1         fuzz ICMP6 echo request (default)\n");
  printf(" -2         fuzz ICMP6 neighbor solicitation\n");
  printf(" -3         fuzz ICMP6 neighbor advertisement\n");
  printf(" -4         fuzz ICMP6 router advertisement\n");
  printf(" -5         fuzz multicast listener report packet\n");
  printf(" -6         fuzz multicast listener done packet\n");
  printf(" -7         fuzz multicast listener query packet\n");
  printf(" -8         fuzz multicast listener v2 report packet\n");
  printf(" -9         fuzz multicast listener v2 query packet\n");
  printf(" -0         fuzz node query packet\n");
  printf(" -s port    fuzz TCP-SYN packet against port\n");
  printf(" -P type    fuzz PIMv2 type packet (hello, bootstrap, assert)\n");
  printf(" -x         tries all 256 values for flag and byte types\n");
  printf(" -t number  continue from test no. number\n");
  printf(" -T number  only performs test no. number\n");
  printf(
      " -p number  perform an alive check every number of tests (default: "
      "none)\n");
  printf(" -a         do not perform initial and final alive test\n");
  printf(" -n number  how many times to send each packet (default: 1)\n");
  printf(" -I         fuzz the IP header too\n");
  printf(" -F         add one-shot fragmentation, and fuzz it too (for 1)\n");
  printf(" -S         add source-routing, and fuzz it too (for 1)\n");
  printf(" -D         add destination header, and fuzz it too (for 1)\n");
  printf(
      " -H         add hop-by-hop header, and fuzz it too (for 1 and 5-9)\n");
  printf(
      " -R         add router alert header, and fuzz it too (for 5-9 and "
      "all)\n");
  printf(" -J         add jumbo packet header, and fuzz it too (for 1)\n");
  //  printf("Use -r to use raw mode.\n");
  printf("You can only define one of -0 ... -9, -P and -s, defaults to -1.\n");
  printf("Note that the -P fuzzing target should be ff02::d\n");
  printf(
      "Returns -1 on error, 0 on tests done and targt alive or 1 on target "
      "crash.\n");
  exit(-1);
}

void addfuzz(char **fuzzbuf, int *fuzzbuf_sz, char *fuzztype) {
  if (strlen(*fuzzbuf) + strlen(fuzztype) + 1 > *fuzzbuf_sz) {
    *fuzzbuf_sz *= 2;
    *fuzzbuf = realloc(*fuzzbuf, *fuzzbuf_sz);
  }
  strcat(*fuzzbuf, fuzztype);
}

void ignoreit(u_char *foo, const struct pcap_pkthdr *header,
              const unsigned char *data) {
  return;
}

int check_alive(pcap_t *p, char *interface, unsigned char *srcmac,
                unsigned char *dstmac, unsigned char *src, unsigned char *dst) {
  int    ret = -2;
  time_t t;

  while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
    ;
  thc_ping26(interface, srcmac, dstmac, src, dst, 16, 1);
  t = time(NULL);
  while (ret < 0) {
    if (thc_pcap_check(p, (char *)ignoreit, NULL) > 0) ret = 1;
    if (time(NULL) > t + 1 && ret == -2) {
      thc_ping26(interface, srcmac, dstmac, src, dst, 16, 1);
      ret = -1;
    }
    if (time(NULL) > t + 4 && ret < 0) ret = 0;
  }

  return ret > 0 ? 1 : 0;
}

int main(int argc, char *argv[]) {
  unsigned char *pkt = NULL, *pkt_bak, *mcast6, *someaddr6 = NULL;
  unsigned char *dst6, *src6 = NULL, *mac = NULL, *routers[2],
                       string[64] = "ip6 and dst ";
  int test_start = 0, fragment = 0, alert = 0, sroute = 0;
  int do_type = DO_PING, do_alive = 1, hopbyhop = 0, destination = 0, jumbo = 0;
  int pkt_len = 0, offset = 0, test_current = 0, i, j, k, do_fuzz = 1,
      test_ptr = 0;
  int test_end = TEST_MAX, ping = NEVER, frag_offset = 0, header = 0,
      no_send = 1;
  int test_pos = 0, test_cnt = 0, do_it, extend = 0, mtu = 1500, size = 64,
      wait = 0, off2 = 14, fuzzbuf_sz = 256;
  char *interface, *fuzzbuf, *srcmac, *dns, *route6, *real_dst6 = NULL,
                                                     *tmp6 = NULL;
  unsigned char       buf[256], buf2[100], buf3[16];
  unsigned short int *sip;
  pcap_t *            p;
  thc_ipv6_hdr *      hdr;

  if (argc < 3 || strncmp(argv[1], "-h", 2) == 0) help(argv[0]);

  while ((i = getopt(argc, argv, "s:0123456789Xxt:T:p:FSDHRIJan:P:")) >= 0) {
    switch (i) {
      case 's':
        do_type = DO_TCP;
        port = atoi(optarg);
        break;
      case '0':
        do_type = DO_NODEQUERY;
        break;
      case '1':
        do_type = DO_PING;
        break;
      case '2':
        do_type = DO_NEIGHSOL;
        break;
      case '3':
        do_type = DO_NEIGHADV;
        break;
      case '4':
        do_type = DO_RA;
        break;
      case '5':
        do_type = DO_MLD_REP;
        break;
      case '6':
        do_type = DO_MLD_DONE;
        break;
      case '7':
        do_type = DO_MLD_QUERY;
        wait = 0xff0000;
        break;
      case '8':
        do_type = DO_MLD2_REPORT;
        break;
      case '9':
        do_type = DO_MLD2_QUERY;
        wait = 0xff0000;
        break;
      case 'P':
        if (strncmp(optarg, "hel", 3) == 0)
          do_type = DO_PIM_HELLO;
        else if (strncmp(optarg, "ass", 3) == 0)
          do_type = DO_PIM_ASSERT;
        else if (strncmp(optarg, "boot", 4) == 0)
          do_type = DO_PIM_BOOTSTRAP;
        else {
          fprintf(stderr, "Error: PIM message type %s is not implemented yet\n",
                  optarg);
          exit(-1);
        }
        break;
      case 'X':
        do_type = DO_NONE;
        break;
      case 't':
        test_start = atoi(optarg);
        break;
      case 'T':
        test_end = test_start = atoi(optarg);
        break;
      case 'p':
        ping = atoi(optarg);
        break;
      case 'a':
        do_alive = 0;
        break;
      case 'S':
        sroute = 1;
        break;
      case 'n':
        no_send = atoi(optarg);
        break;
      case 'F':
        fragment = 1;
        break;
      case 'R':
        alert = 1;
        break;
      case 'D':
        destination = 1;
        break;
      case 'H':
        hopbyhop = 1;
        break;
      case 'J':
        jumbo = 1;
        break;
      case 'I':
        header = 1;
        break;
      case 'x':
        extend = 1;
        break;
    }
  }
  if (argc - optind < 2) {
    fprintf(stderr,
            "ERROR: not enough options, interface and target address are "
            "required!\n");
    exit(-1);
  }
  interface = argv[optind];
  if ((srcmac = thc_get_own_mac(interface)) == NULL) {
    fprintf(
        stderr,
        "ERROR: %s is not a valid interface which has a MAC, use raw mode?\n",
        interface);
    exit(-1);
  }
  if (no_send < 1) {
    fprintf(stderr, "ERROR: -n number must be between one and 2 billion\n");
    exit(-1);
  }
  if (do_hdr_size) {
    test_pos -= do_hdr_size;
    offset -= do_hdr_size;
    off2 = do_hdr_size;
  }
  if (do_type != DO_PING && do_type != DO_TCP && do_type != DO_NONE) {
    if ((mcast6 = thc_resolve6(argv[optind + 1])) == NULL) {
      fprintf(stderr, "Error: %s does not resolve to a valid IPv6 address\n",
              argv[optind + 1]);
      exit(-1);
    }

    if (do_type == DO_NEIGHSOL) {
      dst6 = thc_resolve6("ff02::0001:ff00:0000");
      memcpy(dst6 + 13, mcast6 + 13, 3);
    } else
      dst6 = thc_resolve6("ff02::1");
    if (do_type >= DO_PIM_HELLO && do_type <= DO_PIM_ASSERT)
      dst6 = thc_resolve6("ff02::d");
  } else {
    dst6 = thc_resolve6(argv[optind + 1]);
  }
  if (argv[optind + 1] != NULL)
    if ((real_dst6 = thc_resolve6(argv[optind + 1])) == NULL) {
      fprintf(stderr, "Error: %s does not resolve to a valid IPv6 address\n",
              argv[optind + 1]);
      exit(-1);
    }

  if (interface == NULL || argv[optind + 1] == NULL) {
    printf(
        "Error: interface and target-ipv6-address are mandatory command line "
        "options\n");
    exit(-1);
  }
  if (ping < 1 || test_end < test_start) {
    printf("don't fuck up the command line options!\n");
    exit(-1);
  }
  if (argv[optind + 2] != NULL) someaddr6 = thc_resolve6(argv[optind + 2]);
  if (argc - optind > 3) {
    printf("Error: too many command line options\n");
    exit(-1);
  }
  if ((mac = thc_get_mac(interface, src6, dst6)) == NULL) {
    fprintf(stderr, "ERROR: Can not resolve mac address for %s\n", argv[2]);
    exit(-1);
  }

  if (do_type == DO_PING || do_type == DO_TCP || do_type == DO_NONE)
    src6 = thc_get_own_ipv6(interface, dst6, PREFER_GLOBAL);
  else
    src6 = thc_get_own_ipv6(interface, dst6, PREFER_LINK);
  if (src6 == NULL) {
    fprintf(stderr, "Error: no IPv6 address configured on interface %s\n",
            interface);
    exit(-1);
  }
  strcat(string, thc_ipv62notation(src6));
  if (sroute) {
    if (someaddr6 != NULL)
      routers[0] = someaddr6;
    else
      routers[0] = dst6;
    routers[1] = NULL;
  }
  setvbuf(stdout, NULL, _IONBF, 0);
  memset(buf, 0, sizeof(buf));
  memset(buf2, 0, sizeof(buf2));
  dns = thc_resolve6("ff02::fb");
  route6 = thc_resolve6("2a01::");

  if ((p = thc_pcap_init(interface, string)) == NULL) {
    fprintf(stderr, "Error: could not capture on interface %s with string %s\n",
            interface, string);
    exit(-1);
  }
  if (real_dst6 != NULL && (unsigned char)real_dst6[0] == 0xff) do_alive = 0;
  // ping before to check if it works
  if (do_alive)
    if (check_alive(p, interface, srcmac, mac, src6, real_dst6) == 0) {
      fprintf(stderr, "Error: target %s is not alive via direct ping6!\n",
              argv[optind + 1]);
      exit(-1);
    }
  // generate basic packet
  fuzzbuf = malloc(fuzzbuf_sz);
  fuzzbuf[0] = '\0';
  addfuzz(&fuzzbuf, &fuzzbuf_sz, fuzztype_ether);
  if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src6,
                                      dst6, 0, 0, 0, 0, 0)) == NULL)
    return -1;
  if (header)
    addfuzz(&fuzzbuf, &fuzzbuf_sz, fuzztype_ip6);
  else
    addfuzz(&fuzzbuf, &fuzzbuf_sz, fuzztype_ip6no);

  if (alert || hopbyhop || jumbo) {
    memset(buf2, 0, sizeof(buf2));
    i = 0;

    addfuzz(&fuzzbuf, &fuzzbuf_sz, "XX");  // first two bytes of EH

    if (alert) {
      buf2[i++] = 5;
      buf2[i++] = 2;
      i += 2;
      addfuzz(&fuzzbuf, &fuzzbuf_sz, ".FW");
    }

    if (jumbo) {
      buf2[i++] = 0xc2;
      buf2[i++] = 4;
      buf2[i++] = 'J';  // lookup code
      buf2[i++] = 'J';
      buf2[i++] = 'J';
      buf2[i++] = 'J';
      addfuzz(&fuzzbuf, &fuzzbuf_sz, ".FWW");
    }

    if (hopbyhop) {
      memset(buf3, 0, sizeof(buf3));
      buf3[0] = 'X';
      buf3[1] = '.';
      for (j = 0; j < 10; j++) {
        buf2[i++] = 1;  // PadN, length
        buf2[i++] = j;
        if (j > 0) {
          memset(buf2 + i, 0xaa, j);
          buf3[2 + j] = '.';
          i += j;
        }
        // always: X..... for every new option
        addfuzz(&fuzzbuf, &fuzzbuf_sz, buf3);
      }
    }

    j = 8 - ((i + 2) % 8);
    if (j > 0 && j < 8) {
      for (k = 0; k < j; k++)
        addfuzz(&fuzzbuf, &fuzzbuf_sz, ".");  // fill because of padding
    }

    if (thc_add_hdr_hopbyhop(pkt, &pkt_len, buf2, i) < 0) return -1;

    i += 2;
    if (i % 8 > 0) i = ((i / 8) + 1) * 8;

    offset += i;
  }

  if (sroute) {
    if (thc_add_hdr_route(pkt, &pkt_len, routers, 1) < 0)
      return -1;
    else {
      addfuzz(&fuzzbuf, &fuzzbuf_sz, "FFFFBBBB................");
      offset += 24;
    }
  }

  if (fragment) {
    frag_offset = offset;
    if (thc_add_hdr_fragment(pkt, &pkt_len, 0, 0, 0) < 0)
      return -1;
    else {
      addfuzz(&fuzzbuf, &fuzzbuf_sz, "FFWW..");
      offset += 8;
    }
  }

  if (destination) {
    memset(buf2, 0, sizeof(buf2));
    memset(buf3, 0, sizeof(buf3));
    addfuzz(&fuzzbuf, &fuzzbuf_sz, "XX");  // first two bytes of EH
    buf3[0] = 'X';
    buf3[1] = '.';
    i = 0;
    for (j = 0; j < 10; j++) {
      buf2[i++] = 1;  // PadN, length
      buf2[i++] = j;
      if (j > 0) {
        memset(buf2 + i, 0xaa, j);
        buf3[2 + j] = '.';
        i += j;
      }
      // always: X... for every new option
      addfuzz(&fuzzbuf, &fuzzbuf_sz, buf3);
    }

    j = 8 - ((i + 2) % 8);
    if (j > 0 && j < 8) {
      for (k = 0; k < j; k++)
        addfuzz(&fuzzbuf, &fuzzbuf_sz, ".");  // fill because of padding
    }

    if (thc_add_hdr_dst(pkt, &pkt_len, buf2, i) < 0) return -1;

    i += 2;
    if (i % 8 > 0) i = ((i / 8) + 1) * 8;

    offset += i;
  }

  memset(buf, 0, sizeof(buf));
  //  if (header)
  addfuzz(&fuzzbuf, &fuzzbuf_sz, fuzztype_icmp6);
  //  else
  //    addfuzz(&fuzzbuf, &fuzzbuf_sz, fuzztype_icmp6no);
  switch (do_type) {
    case DO_TCP:
      // tcp options
      buf[0] = 2;  // max segment size
      buf[1] = 4;
      buf[2] = 255;
      buf[3] = 255;
      buf[4] = 3;  // windows size
      buf[5] = 3;
      buf[6] = 62;
      buf[7] = 1;  // padding
      buf[8] = 8;  // timestamp
      buf[9] = 10;
      buf[10] = time(NULL) / 16777216;
      buf[11] = ((time(NULL) / 65536) % 256);
      buf[12] = ((time(NULL) / 256) % 256);
      buf[13] = time(NULL) % 256;
      // 4 bytes ack tstamp 00000000
      // rest is padding (2 bytes)
      if (thc_add_tcp(pkt, &pkt_len, 65532, port, test_current, 0, TCP_SYN,
                      5760, 0, (unsigned char *)buf, 20, (unsigned char *)buf,
                      20) < 0)
        return -1;
      addfuzz(&fuzzbuf, &fuzzbuf_sz, fuzztype_tcp);
      break;

    case DO_PING:
      if (thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, test_current,
                        (unsigned char *)&buf, 16, 0) < 0)
        return -1;
      addfuzz(&fuzzbuf, &fuzzbuf_sz, fuzztype_icmp6ping);
      break;

    case DO_PIM_HELLO:
      buf[1] = 1;  // opt 1
      buf[3] = 2;  // len 2
      buf[5] = 255;
      buf[7] = 19;  // opt 19
      buf[9] = 4;   // len 4
      buf[13] = 2;
      buf[15] = 20;  // opt 20
      buf[17] = 4;   // len 4
      // buf 18, 4 bytes: rand counter
      i = time(NULL);
      memcpy(buf + 18, (char *)&i + _TAKE4, 4);
      buf[23] = 2;  // opt 2
      buf[25] = 4;  // len 4
      memset(buf + 26, 0x01, 4);
      buf[31] = 24;  // opt 24
      buf[33] = 18;  // len 18
      buf[34] = 2;
      if (someaddr6 == NULL)
        tmp6 = thc_get_own_ipv6(interface, dst6, PREFER_GLOBAL);
      else
        tmp6 = someaddr6;
      memcpy(buf + 36, tmp6, 16);

      if (thc_add_pim(pkt, &pkt_len, do_type, buf, 52) < 0) return -1;
      addfuzz(&fuzzbuf, &fuzzbuf_sz, fuzztype_pim_hello);
      break;

    case DO_PIM_BOOTSTRAP:
      buf[0] = 5;
      buf[1] = 0x7d;
      buf[3] = 1;
      buf[4] = 2;
      if (someaddr6 == NULL)
        tmp6 = thc_get_own_ipv6(interface, dst6, PREFER_GLOBAL);
      else
        tmp6 = someaddr6;
      memcpy(buf + 6, tmp6, 16);
      buf[22] = 2;
      buf[25] = 40;  // mask
      tmp6 = thc_resolve6("ff00::");
      memcpy(buf + 26, tmp6, 16);  // buf + 27 <= rand
      buf[42] = 1;
      buf[43] = 1;
      buf[46] = 2;
      tmp6 = thc_get_own_ipv6(interface, dst6, PREFER_GLOBAL);
      memcpy(buf + 48, tmp6, 16);
      buf[65] = 0x96;  // holdtime
      buf[66] = 7;     // prio

      if (someaddr6 == NULL)
        tmp6 = thc_get_own_ipv6(interface, dst6, PREFER_GLOBAL);
      else
        tmp6 = someaddr6;
      memcpy(buf + 36, tmp6, 16);

      if (thc_add_pim(pkt, &pkt_len, do_type, buf, 68) < 0) return -1;
      addfuzz(&fuzzbuf, &fuzzbuf_sz, fuzztype_pim_bootstrap);
      break;

    case DO_PIM_ASSERT:
      buf[0] = 2;
      buf[3] = 16;
      if (someaddr6 != NULL && someaddr6[0] == 0xff)
        tmp6 = someaddr6;
      else
        tmp6 = thc_resolve6("ff05::3");
      memcpy(buf + 4, tmp6, 16);
      buf[20] = 2;
      buf[32 + 6] = 0x80;
      buf[34 + 6] = 1;  // metric 256
      buf[38 + 6] = 1;

      if (thc_add_pim(pkt, &pkt_len, do_type, buf, 46) < 0) return -1;
      addfuzz(&fuzzbuf, &fuzzbuf_sz, fuzztype_pim_assert);
      break;

    case DO_NONE:
      // empty
      break;

    case DO_NEIGHSOL:
      if (someaddr6 != NULL)
        memcpy(buf, someaddr6, 16);
      else
        memcpy(buf, mcast6, 16);
      buf[16] = 1;
      buf[17] = 1;
      memcpy(buf + 18, srcmac, 6);
      if (thc_add_icmp6(pkt, &pkt_len, ICMP6_NEIGHBORSOL, 0, 0,
                        (unsigned char *)&buf, 24, 0) < 0)
        return -1;
      addfuzz(&fuzzbuf, &fuzzbuf_sz, fuzztype_icmp6ns);
      break;

    case DO_NEIGHADV:
      if (someaddr6 != NULL)
        memcpy(buf, someaddr6, 16);
      else
        memcpy(buf, src6, 16);
      buf[16] = 2;
      buf[17] = 1;
      memcpy(buf + 18, srcmac, 6);
      if (thc_add_icmp6(pkt, &pkt_len, ICMP6_NEIGHBORADV, 0, 0xe0000000,
                        (unsigned char *)&buf, 24, 0) < 0)
        return -1;
      addfuzz(&fuzzbuf, &fuzzbuf_sz, fuzztype_icmp6na);
      break;

    case DO_NODEQUERY:
      memcpy(buf + 8, real_dst6, 16);
      if (thc_add_icmp6(pkt, &pkt_len, ICMP6_NODEQUERY, 0, 0x0003003e,
                        (unsigned char *)&buf, 24, 0) < 0)
        return -1;
      addfuzz(&fuzzbuf, &fuzzbuf_sz, fuzztype_icmp6nq);
      break;

    case DO_RA:
      //  buf[3] = 250; // 0-3: reachable timer
      buf[6] = 4;  // 4-7: retrans timer
      // option mtu
      buf[8] = 5;
      buf[9] = 1;
      buf[12] = mtu / 16777216;

      buf[14] = (mtu % 65536) / 256;
      buf[15] = mtu % 256;
      // option prefix
      buf[16] = 3;
      buf[17] = 4;
      buf[18] = size;  // prefix length
      buf[19] = 128 + 64;
      memset(&buf[20], 17, 4);
      memset(&buf[24], 4, 4);
      if (someaddr6 != NULL)
        memcpy(&buf[32], someaddr6, 16);
      else
        memcpy(&buf[32], route6, 16);

      i = 48;
      // mac address option
      buf[i++] = 1;
      buf[i++] = 1;
      memcpy(buf + i, srcmac, 6);
      i += 6;  // = 8 == 56

      // default route routing option
      buf[i++] = 0x18;  // routing entry option type
      buf[i++] = 0x03;  // length 3 == 24 bytes
      buf[i++] = 64;    // prefix length /64
      buf[i++] = 0x08;  // priority, highest of course
      i += 2;           // 52-53 unknown
      buf[i++] = 0x11;  // lifetime, word
      buf[i++] = 0x11;  // lifetime, word
      buf[i++] = 0x20;
      buf[i++] = 4;  // 56-71 address, 2004:: for default
      i += 14;       // = 24 == 70

      // dns option
      buf[i++] = 0x19;        // dns option type
      buf[i++] = 0x03;        // length
      i += 2;                 // 74-75 reserved
      memset(buf + i, 1, 4);  // validity time
      i += 4;
      if (someaddr6 != NULL)
        memcpy(buf + i, someaddr6, 16);  // dns server
      else
        memcpy(buf + i, dns, 16);  // dns server
      i += 16;                     // = 24 == 94

      // seachlist option
      buf[i++] = 31;
      buf[i++] = 4;
      i += 2;
      memset(buf + i, 1, 4);  // validity time
      i += 4;
      buf[i++] = 3;
      memcpy(buf + i, "foo", 3);
      i += 3;
      buf[i++] = 4;
      memcpy(buf + i, "corp", 4);
      i += 5;  // + null byte
      buf[i++] = 5;
      memcpy(buf + i, "local", 5);
      i += 5;
      buf[i++] = 6;
      memcpy(buf + i, "domain", 6);
      i += 7;  // + null byte
      // = 32 == 126

      // flag extension option
      buf[i++] = 26;
      buf[i++] = 1;
      buf[i++] = 0x08;
      i += 5;

      if (thc_add_icmp6(pkt, &pkt_len, ICMP6_ROUTERADV, 0, 0xff080800, buf, i,
                        0) < 0)
        return -1;
      addfuzz(&fuzzbuf, &fuzzbuf_sz, fuzztype_icmp6ra);
      break;

    case DO_MLD_QUERY:
    case DO_MLD_DONE:
    case DO_MLD_REP:
      buf[0] = 0xff;
      buf[1] = 0x02;
      buf[15] = 0x05;
      if (someaddr6 != NULL) memcpy(buf, someaddr6, 16);
      if (thc_add_icmp6(pkt, &pkt_len, do_type, 0, wait, buf, 16, 0) < 0)
        return -1;
      addfuzz(&fuzzbuf, &fuzzbuf_sz, fuzztype_icmp6mld);
      break;
    case DO_MLD2_QUERY:
      buf[0] = 0xff;
      buf[1] = 0x02;
      buf[15] = 0x05;
      if (someaddr6 != NULL) memcpy(buf, someaddr6, 16);
      buf[16] = 7;
      buf[17] = 120;
      buf[19] = 3;
      memcpy(buf + 20, dst6, 16);
      memcpy(buf + 36, buf, 16);
      if (thc_add_icmp6(pkt, &pkt_len, DO_MLD_QUERY, 0, wait, buf, 68, 0) < 0)
        return -1;
      addfuzz(&fuzzbuf, &fuzzbuf_sz, fuzztype_icmp6mld2que);
      break;
    case DO_MLD2_REPORT:
      for (i = 0; i < 3; i++) {
        buf[0 + 68 * i] =
            1 + i * 2 - i / 2;  // include new++, generates 1, 3 and 4
        buf[3 + 68 * i] = 3;    // 3 sources
        buf[4 + 68 * i] = 0xff;
        buf[5 + 68 * i] = 0x02;
        buf[18 + 68 * i] = 0x82 + i % 256;
        buf[19 + 68 * i] = 0xff;
        memcpy(buf + 20 + 68 * i, src6, 16);
        buf[36 + 68 * i] = 0xfe;
        buf[37 + 68 * i] = 0x80;
        buf[46 + 68 * i] = 0xf0;
        if (someaddr6 != NULL) memcpy(buf + 52 + 68 * i, someaddr6, 16);
      }

      if (thc_add_icmp6(pkt, &pkt_len, do_type, 0, 3, buf, 208, 0) < 0)
        return -1;
      addfuzz(&fuzzbuf, &fuzzbuf_sz, fuzztype_icmp6mld2rep);
      break;

    default:
      fprintf(stderr, "ERROR: Mode not implemented yet!\n");
      exit(-1);
  }

  if (thc_generate_pkt(interface, srcmac, mac, pkt, &pkt_len) < 0) return -1;
  hdr = (thc_ipv6_hdr *)pkt;

  if (jumbo) {
    i = 0;
    j = 1;
    while (i < hdr->pkt_len + 4 && j) {
      if (hdr->pkt[i] == 'J')
        if (memcmp(&hdr->pkt[i], "JJJJ", 4) == 0) j = 0;
      i++;
    }
    if (j) {
      fprintf(stderr, "ERROR: fuckup, cant find my own marker?!\n");
      exit(-1);
    } else
      i--;
    hdr->pkt[i] = 0;
    hdr->pkt[i + 1] = 0;
    hdr->pkt[i + 2] = hdr->pkt[4 + off2];
    hdr->pkt[i + 3] = hdr->pkt[5 + off2];
    hdr->pkt[4 + off2] = 0;
    hdr->pkt[5 + off2] = 0;
  }

  if (extend)
    for (i = 0; i < strlen(fuzzbuf); i++)
      if (fuzzbuf[i] == 'B' || fuzzbuf[i] == 'F') fuzzbuf[i] = 'X';

  // backup of generated packet
  pkt_bak = malloc(hdr->pkt_len);
  memcpy(pkt_bak, hdr->pkt, hdr->pkt_len);

  printf(
      "Fuzzing packet, starting at fuzz case %d, ending at fuzz case %d, every "
      "packet sent denoted by a dot:\n",
      test_start, test_end);
  // printf("buf(%d): %s\n", strlen(fuzzbuf), fuzzbuf);
  while (do_fuzz) {
    if (test_cnt == 0)
      while (fuzzbuf[test_ptr] == '.') {
        test_ptr++;
        test_pos++;
      }

    if (fuzzbuf[test_ptr] == 0) do_fuzz = 0;

    test_cnt++;
    do_it = 1;

    // printf("[%s] pos[%d]=%c -> %d | pkt[%d] | %d (%d=>%d)| ", /*fuzzbuf*/"",
    // test_ptr, fuzzbuf[test_ptr], test_cnt, test_pos, test_current, test_start,
    // test_end);
    switch (fuzzbuf[test_ptr]) {
      case 0:
        break;
      case 'X':
        if (test_cnt <= COUNT_EXTEND) {
          if (pkt_bak[test_pos] != extends[test_cnt - 1])
            hdr->pkt[test_pos] = extends[test_cnt - 1];
          else
            do_it = 0;
        } else {
          test_cnt = 0;
          test_ptr++;
          test_pos++;
        }
        break;
      case 'B':
        if (test_cnt <= COUNT_BYTE) {
          if (pkt_bak[test_pos] != bytes[test_cnt - 1])
            hdr->pkt[test_pos] = bytes[test_cnt - 1];
          else
            do_it = 0;
        } else {
          i = 0;
          while (i < COUNT_BYTE && do_it) {
            if (bytes[i] == pkt_bak[test_pos]) do_it = 0;
            i++;
          }
          if (do_it)
            hdr->pkt[test_pos] =
                hdr->pkt[test_pos] ^ xors[test_cnt - COUNT_BYTE - 1];
        }
        if (test_cnt == COUNT_BYTE + COUNT_XOR) {
          test_cnt = 0;
          test_ptr++;
          test_pos++;
        }
        break;
      case 'F':
        if (test_cnt <= COUNT_FLAG) {
          if (pkt_bak[test_pos] != flags[test_cnt - 1])
            hdr->pkt[test_pos] = flags[test_cnt - 1];
          else
            do_it = 0;
        } else {
          i = 0;
          while (i < COUNT_BYTE && do_it) {
            if (bytes[i] == pkt_bak[test_pos])  // yes, bytes[] is the right one
                                                // even for flags
              do_it = 0;
            i++;
          }
          if (do_it)
            hdr->pkt[test_pos] =
                hdr->pkt[test_pos] ^ xors[test_cnt - COUNT_BYTE - 1];
        }
        if (test_cnt == COUNT_FLAG + COUNT_XOR) {
          test_cnt = 0;
          test_ptr++;
          test_pos++;
        }
        break;
      case 'W':
        sip = (unsigned short int *)&pkt_bak[test_pos];
        if (test_cnt <= COUNT_WORD) {
          if (*sip != words[test_cnt - 1])
            memcpy((char *)&hdr->pkt[test_pos],
                   (char *)&words[test_cnt - 1] + _TAKE2, 2);
          else
            do_it = 0;
        } else {
          i = 0;
          while (i < COUNT_WORD && do_it) {
            if (words[i] == *sip) do_it = 0;
            i++;
          }
          if (do_it) {
            i = *sip ^ xors[test_cnt - COUNT_WORD - 1];
            sip = (unsigned short int *)&hdr->pkt[test_pos];
            *sip = i % 65536;
          }
        }
        if (test_cnt == COUNT_WORD + COUNT_XOR) {
          test_cnt = 0;
          test_ptr++;
          test_pos += 2;
        }
        break;
      default:
        fprintf(stderr,
                "This character should not be in the fuzz string, shoot the "
                "programmer: %c(%d) position %d string %s\n",
                fuzzbuf[test_ptr], fuzzbuf[test_ptr], test_ptr, fuzzbuf);
        exit(-1);
        break;
    }

    if (do_it && do_fuzz) {
      if (test_current >= test_start && test_current <= test_end && do_fuzz) {
        // fill icmp id+seq and unique buffer with test case number
        if (fragment)
          memcpy(hdr->pkt + frag_offset + 58, (char *)&test_current + _TAKE4,
                 4);
        switch (do_type) {
          case DO_NONE:
            // empty
            break;
          case DO_PING:
            for (i = 0; i < 4 + 1; i++)
              memcpy(hdr->pkt + offset + 58 + i * 4,
                     (char *)&test_current + _TAKE4, 4);
            break;
          case DO_TCP:
            memcpy(hdr->pkt + offset + 58, (char *)&test_current + _TAKE4, 4);
            break;
          case DO_PIM_HELLO:
            memcpy(hdr->pkt + offset + 62 + 14, (char *)&test_current + _TAKE4,
                   4);  // TEST BUG FIXME XXX
            break;
          case DO_PIM_ASSERT:
            memcpy(hdr->pkt + offset + 60 + 14, (char *)&test_current + _TAKE4,
                   4);  // TEST BUG FIXME XXX
            break;
          case DO_PIM_BOOTSTRAP:
            memcpy(hdr->pkt + offset + 71 + 14, (char *)&test_current + _TAKE4,
                   4);  // TEST BUG FIXME XXX
            break;
          case DO_NEIGHSOL:
          case DO_NEIGHADV:
            break;  // do nothing for these
          case DO_NODEQUERY:
            memcpy(hdr->pkt + offset + 66, (char *)&test_current + _TAKE4, 4);
            break;
          case DO_RA:
            memcpy(hdr->pkt + offset + 0x62, (char *)&test_current + _TAKE4,
                   4);  // prefix update
            memcpy(hdr->pkt + offset + 0x7e, hdr->pkt + offset + 0x5e,
                   16);  // routing update
            memcpy(hdr->pkt + 8, (char *)&test_current + _TAKE4,
                   4);  // srcmac update
            memcpy(hdr->pkt + offset + 0x72, (char *)&test_current + _TAKE4,
                   4);  // srcmac update
            memcpy(hdr->pkt + 0x10 + off2, (char *)&test_current + _TAKE4,
                   4);  // srcip update
            memcpy(hdr->original_src, hdr->pkt + 8 + off2,
                   16);  // srcip update for checksum
            break;
          case DO_MLD_QUERY:
          case DO_MLD_DONE:
          case DO_MLD_REP:
          case DO_MLD2_QUERY:
            memcpy(hdr->pkt + offset + 0x4a, (char *)&test_current + _TAKE4, 4);
            break;
          case DO_MLD2_REPORT:  //??? XXX TODO CHECK
            memcpy(hdr->pkt + offset + 0x4d, (char *)&test_current + _TAKE4, 4);
            memcpy(hdr->pkt + offset + 0x4d + 68,
                   (char *)&test_current + _TAKE4, 4);
            memcpy(hdr->pkt + offset + 0x4d + 136,
                   (char *)&test_current + _TAKE4, 4);
            break;
          default:
            fprintf(stderr, "ERROR!!!\n");
            exit(-1);
        }

        // regenerate checksum
        if (do_type != DO_TCP && do_type != DO_NONE &&
            (do_type < DO_PIM_HELLO ||
             do_type > DO_PIM_ASSERT)) {  // maybe for later non-icmp stuff
          hdr->pkt[offset + 56] = 0;
          hdr->pkt[offset + 57] = 0;
          i = checksum_pseudo_header(hdr->original_src, hdr->final_dst,
                                     NXT_ICMP6, &hdr->pkt[offset + 54],
                                     hdr->pkt_len - offset - 54);
          hdr->pkt[offset + 56] = i / 256;
          hdr->pkt[offset + 57] = i % 256;
        } else if (do_type >= DO_PIM_HELLO && do_type <= DO_PIM_ASSERT) {
          hdr->pkt[offset + 56] = 0;
          hdr->pkt[offset + 57] = 0;
          i = checksum_pseudo_header(hdr->original_src, hdr->final_dst, NXT_PIM,
                                     &hdr->pkt[offset + 54],
                                     hdr->pkt_len - offset - 54);
          hdr->pkt[offset + 56] = i / 256;
          hdr->pkt[offset + 57] = i % 256;
        } else {  // TCP
          hdr->pkt[offset + 70] = 0;
          hdr->pkt[offset + 71] = 0;
          i = checksum_pseudo_header(hdr->original_src, hdr->final_dst, NXT_TCP,
                                     &hdr->pkt[offset + 54],
                                     hdr->pkt_len - offset - 54);
          hdr->pkt[offset + 70] = i / 256;
          hdr->pkt[offset + 71] = i % 256;
        }
        // send packet
        for (k = 0; k < no_send; k++) {
          while (thc_send_pkt(interface, pkt, &pkt_len) < 0)
            usleep(1);
        }
        printf(".");
        usleep(250);
        // if ping, check ping again
        if ((test_current - test_start) % ping == 0 && test_current != 0 &&
            test_start != test_current)
          if (check_alive(p, interface, srcmac, mac, src6, real_dst6) == 0) {
            i = ((((test_current - test_start) / ping) - 1) * ping) +
                test_start + 1;
            printf(
                "\nResult: target %s crashed during fuzzing, offending test "
                "case no. could be %d to %d\n",
                argv[optind + 1], i < 0 ? 0 : i, test_current);
            exit(1);
          }
      }
      // else printf("NOT SENT - NOT IN TEST LIST\n");
      // reset to basic packet
      memcpy(hdr->pkt, pkt_bak, hdr->pkt_len);
      test_current++;
    }
    // else printf("NOT SENT!\n");
  }

  printf("\n");
  // ping afterwards to check if it worked
  if (do_alive) {
    if (check_alive(p, interface, srcmac, mac, src6, real_dst6) == 0) {
      printf(
          "Result: target %s is NOT alive via direct ping6 - good work! "
          "(position: %d)\n",
          argv[optind + 1], test_pos);
      exit(1);
    } else
      printf(
          "Result: target %s is still alive via direct ping6, better luck next "
          "time.\n",
          argv[optind + 1]);
  }

  thc_pcap_close(p);
  return 0;
}
