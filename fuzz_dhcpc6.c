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
#include <netinet/in.h>
#include <sys/select.h>
#include "thc-ipv6.h"

int do_fuzzer();

#define COUNT_FLAG 11
#define COUNT_BYTE 4
#define COUNT_WORD 16
#define COUNT_XOR 2
#define COUNT_EXTEND 256
#define COUNT_DWORD 256

#define NEVER 2000000000
#define TEST_MAX (NEVER - 1)

#define DO_SOL 1
#define DO_ADV 2
#define DO_REQ 3
#define DO_CON 4
#define DO_REN 5
#define DO_REB 6
#define DO_REP 7
#define DO_REL 8
#define DO_DEC 9
#define DO_REC 10
#define DO_NFO 11
#define DO_REL_FOR 12
#define DO_REL_REP 13

/*
 * Fuzzing data types:
 *  F = flags = 1 byte = 8 bits | flags | 8 ; 256
 *  B = byte = 1 byte | 0 1 254 255 xor XOR | 6 ; 256
 *  X = byte = 1 byte | all values from 0 to 255
 *  W = word = 2 bytes | 0,1,254,255^2 xor XOR | 18 ; 65536
 *  D = double word = 4 bytes | {0,1,254,255}^4 xor XOR | 258 ; 4294967295
 *  . = byte = ignore, jump over
 *
 */
struct OPT {
  char tag;
  char fuzz[45];
  char dont_fuzz[45];
  char label[45];
  char code[45];
  int  length;
} options[22] = {
    {'x', "Xx", ".x", "DCHP MESSAGE TYPE", {0x02}, 1},
    {'y', "BBBy", "...y", "TRANSACTION ID", {0x00, 0x00, 0x00}, 3},
    {'z',
     "....WWDWWWz",
     "..................z",
     "CLIENTID",
     {0x00, 0x01, 0x00, 0x0E, 'C', 'L', 'I', 'E', 'N', 'T', ' ', 'I', 'D', ' ',
      'D', 'U', 'I', 'D'},
     18},
    {'a',
     "....WWDWWWa",
     "..................a",
     "SERVERID (a)",
     {0x00, 0x02, 0x00, 0x0E, 0x00, 0x01, 0x00, 0x01, 0x1A, 0x62, 0xB6, 0x77,
      'D', 'I', 'D', 'U', 'I', 'D'},
     18},
    {'b',
     "....DDDb",
     "................b",
     "IA_NA (b)",
     {0x00, 0x03, 0x00, 0x0C, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x0A},
     16},
    {'c',
     "....DWWWWc",
     "................c",
     "IA_TA (c)",
     {0x00, 0x04, 0x00, 0x0C, 0x01, 0x02, 0x03, 0x04, 0x00, 0x0D, 0x00, 0x04,
      0x00, 0x00, 'O', 'K'},
     16},
    {'d',
     "................DD...Xd",
     "............................d",
     "IAADR (d)",
     {
         0x00, 0x05, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x0D, 0x00, 0x00,
     },
     28},
    {'e',
     "....XXe",
     "......e",
     "ORO (e)",
     {0x00, 0x06, 0x00, 0x02, 0x00, 0x08},
     6},
    {'f',
     "....Xf",
     ".....f",
     "PREFERENCE (f)",
     {0x00, 0x07, 0x00, 0x01, 0x00},
     5},
    {'g',
     "....BBg",
     "......g",
     "ELAPSED_TIME (g)",
     {0x00, 0x08, 0x00, 0x02, 0x10, 0xFF},
     6},
    {'h',
     ".....BB...............B...............h",
     "......................................h",
     "RELAY_MSG (h)",
     {0x00, 0x09, 0x00, 0x22, 0x0C, 0x0F, 'L',  'I', 'N',  'K',
      ' ',  'A',  'D',  'D',  'R',  'E',  'S',  'S', 0x0D, 0x0E,
      0x0F, 0x10, 'P',  'E',  'E',  'R',  ' ',  'A', 'D',  'D',
      'R',  'E',  'S',  'S',  0x0D, 0x0E, 0x0F, 0x10},
     38},
    {'i',
     "....BBBDD.....DB................i",
     ".........................................i",
     "AUTHENTICATION (i)",
     {0x00, 0x0B, 0x00, 0x25, 0x00, 0x01, 0x00, 'R', 'E', 'P', 'L',
      'A',  'Y',  0x07, 0x08, 'R',  'E',  'A',  'L', 'M', 'K', 'E',
      'Y',  0x04, 0x05, 'H',  'M',  'A',  'C',  '-', 'M', 'D', '5',
      0x09, 0x0A, 0xB,  0x0C, 0x0D, 0x0E, 0x0F, 0x10},
     41},
    {'j',
     "....DDDDj",
     "....................j",
     "UNICAST (j)",
     {0x00, 0x0C, 0x00, 0x10, 'U', 'N', 'I', 'C', 'A', 'S',
      'T',  ' ',  'A',  'D',  'D', 'R', 'E', 'S', 'S', 0x10},
     20},
    {'k',
     "....XX..............k",
     "....................k",
     "STATUS_CODE (k)",
     {0x00, 0x0D, 0x00, 0x10, 0x00, 0x00, 'S', 'T', 'A', 'T',
      'U',  'S',  ' ',  'M',  'E',  'S',  'S', 'A', 'G', 'E'},
     20},
    {'l', "...Bl", "....l", "RAPID_COMMIT (l)", {0x00, 0x0E, 0x00, 0x00}, 4},
    {'m',
     "......Dm",
     "..........m",
     "USER_CLASS (m)",
     {0x00, 0x0F, 0x00, 0x06, 0x00, 0x04, 'U', 'S', 'E', 'R'},
     10},
    {'n',
     "....D.......n",
     "...............n",
     "VENDOR_CLASS (n)",
     {0x00, 0x10, 0x00, 0x0B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 'C', 'L', 'A',
      'S', 'S'},
     15},
    {'o',
     "....D..........o",
     "..................o",
     "VENDOR_OPTS (o)",
     {0x00, 0x11, 0x00, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
      'O', 'P', 'T', 'I', 'O', 'N'},
     18},
    {'p',
     ".................Bp",
     "..................p",
     "INTERFACE_ID (p)",
     {0x00, 0x12, 0x00, 0x0E, 'I', 'N', 'T', 'E', 'R', 'F', 'A', 'C', 'E', ' ',
      'I', 'D', ' ', ' '},
     18},
    {'q',
     "....Xq",
     ".....q",
     "RECONF_MSG (q)",
     {0x00, 0x13, 0x00, 0x01, 0x00},
     5},
    {'r',
     "....Br",
     ".....r",
     "RECONF_ACCEPT (r)",
     {0x00, 0x14, 0x00, 0x01, 0x00},
     5},
    {'s', "", "", "FUZZING BUFFER ERROR! (s)", {0x00}, 1},
};

unsigned short int words[] = {0x0000, 0x0001, 0x00fe, 0x00ff, 0x0100, 0x0101,
                              0x01fe, 0x01ff, 0xfe00, 0xfe01, 0xfefe, 0xfeff,
                              0xff00, 0xff01, 0xfffe, 0xffff};  // 16

unsigned int xors[] = {0, 0xffffffff};  // 2

unsigned char extends[] = {
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

char           tribyte_id[4] = {0, 0, 0, 0};
int            fdebug = 0;
unsigned char *dst;
unsigned char  flags[] = {0, 1, 2, 4, 8, 16, 32, 64, 128, 254, 255};  // 11
unsigned char  bytes[] = {0, 1, 254, 255};                            // 4
char           mac[6] = {0, 0x0c, 0, 0, 0, 0},
     *pkt = NULL;     // defines mac as 6 pieces and defines pkt as null.
char wdatabuf[2048];  // builds data buffer and sets memory size at 1024mb
unsigned char *mac6 = mac, *src;  // creates mac6 address usuing
int           i, s, len, pkt_len = 0, dlen = 0;
int           do_all = 1, use_real_mac = 1, use_real_link = 1;
int           port = -1;
int           listen_for_clients = 1;
char          victim[128] = "fe80::20c:29ff:fe3f:e572";
int           cidflag = 0;
int           oflg = 0;
int           f_cnt = 0;
int           p_cnt = 0;
unsigned char cid[14] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
int           lidx = 0;
char          mac_fuzz[] = "..............";
char          ipv6_fuzz[] = "........................................";
char          udp_header_fuzz[] = "........";
char          option_string[100] = "abcdefghijklmnopqr";
char          fuzzing_mask[512];
char *        interface = NULL;
int           test_start = 0, test_end = TEST_MAX, ping = NEVER, no_send = 1,
    got_packet = 0;
int                     xid = 0;
pcap_t *                p = NULL;
int                     do_type = DO_ADV, fuzz_dhcp_msg = 0;
unsigned char           rdatabuf[1024];
unsigned char *         ptr1, *ptr2;
static struct iovec     iov;
struct sockaddr_storage from;
struct msghdr           mhdr;
struct sockaddr_in6     ddst;
char                    cmsgbuf[1024];
int                     fromlen = 0, len, s, t;

void help(char *prg) {
  printf("%s %s (c) 2022 by %s %s\n", prg, VERSION, "Darrell Ambro", RESOURCE);
  printf("Partially based on code by Brandon Hutcheson and Graeme Neilson\n\n");
  printf(
      "Syntax: %s  [-1|-2|-3|-4|-5|-6|-7|-8|-9|-A|-B|-C|-D|-m] -f mac -l link "
      "-v ipv6 -x xid -c client -o options interface\n\n",
      prg);
  printf("Options:\n");
  printf("  -1         fuzz DHCPv6 Solicit\n");
  printf("  -2         fuzz DHCPv6 Advertise (default)\n");
  printf("  -3         fuzz DHCPv6 Request\n");
  printf("  -4         fuzz DHCPv6 Confirm\n");
  printf("  -5         fuzz DHCPv6 Renew\n");
  printf("  -6         fuzz DHCPv6 Rebind\n");
  printf("  -7         fuzz DHCPv6 Reply\n");
  printf("  -8         fuzz DHCPv6 Release\n");
  printf("  -9         fuzz DHCPv6 Decline\n");
  printf("  -A         fuzz DHCPv6 Reconfigure\n");
  printf("  -B         fuzz DHCPv6 Information Request\n");
  printf("  -C         fuzz DHCPv6 Relay-Forward\n");
  printf("  -D         fuzz DHCPv6 Relay-reply\n");
  printf("  -m         fuzz the message type as well\n");
  printf(
      "  -v ipv6    IPv6 address of victim (if not specified DHCP clients "
      "sending messages are attacked)\n");
  printf(
      "  -x xid     Transaction ID of victim - zero for random (ignored if -v "
      "not specified) \n");
  printf(
      "  -c client  Client ID of victim - zero for random (ignored if -v not "
      "specified) \n");
  printf("  -f mac     spoof the mac address\n");
  printf("  -l link    spoof the link address\n");
  printf(
      "  -o options DHCPv6 message options to send (default: "
      "abcdefghijklmonpqr)\n");
  printf("       a  OPTION_SERVERID\n");
  printf("       b  OPTION_IA_NA\n");
  printf("       c  OPTION_IA_TA\n");
  printf("       d  OPTION_IAADR\n");
  printf("       e  OPTION_ORO\n");
  printf("       f  OPTION_PREFERENCE\n");
  printf("       g  OPTION_ELAPSED_TIME\n");
  printf("       h  OPTION_RELAY_MSG\n");
  printf("       i  OPTION_AUTH\n");
  printf("       j  OPTION_UNICAST\n");
  printf("       k  OPTION_STATUS_CODE\n");
  printf("       l  OPTION_RAPID_COMMIT\n");
  printf("       m  OPTION_USER_CLASS\n");
  printf("       n  OPTION_VENDOR_CLASS\n");
  printf("       o  OPTION_VENDOR_OPTS\n");
  printf("       p  OPTION_INTERFACE_ID\n");
  printf("       q  OPTION_RECONF_MSG\n");
  printf("       r  OPTION_RECONF_ACCEPT\n");
  printf("\nFuzz messages sent to a DHCPv6 client\n");
  exit(-1);
}

int fuzz_loop(char *pkt, int *pkt_len) {
  int do_fuzz = 1;
  int test_pos = 0, test_ptr = 0, test_cnt = 0, test_current = 0;
  int do_it;
  int i;
  unsigned short int *sip;
  unsigned int *      intp;
  int                 fragment = 0, frag_offset = 0;
  unsigned char *     pkt_bak;
  thc_ipv6_hdr *      hdr = (thc_ipv6_hdr *)pkt;

  // backup of generated packet
  pkt_bak = malloc(hdr->pkt_len);
  memcpy(pkt_bak, hdr->pkt, hdr->pkt_len);

  if (fdebug)
    printf("fuzzing_mask(%lu): %s\n", strlen(fuzzing_mask), fuzzing_mask);
  if (fdebug) printf("Victim: %s\n", victim);
  while (do_fuzz) {
    if (test_cnt == 0)
      while (fuzzing_mask[test_ptr] == '.') {
        test_ptr++;
        test_pos++;
      }
    if ((int)fuzzing_mask[test_ptr] >= 'a') {
      for (lidx = 0; lidx < 21; ++lidx)
        if (fuzzing_mask[test_ptr] == options[lidx].tag) break;
      if (f_cnt == 0) {
        printf("%s not fuzzed\n", options[lidx].label);
      } else {
        if (options[lidx].tag < 's' || options[lidx].tag == 'z')
          printf("OPTION_%s %d messages (%d)\n", options[lidx].label, f_cnt,
                 p_cnt + f_cnt);
        else
          printf("%s %d messages (%d)\n", options[lidx].label, f_cnt,
                 p_cnt + f_cnt);
      }
      test_ptr++;
      p_cnt += f_cnt;
      f_cnt = 0;
      continue;
    }

    if (fuzzing_mask[test_ptr] == 0) do_fuzz = 0;

    test_cnt++;
    do_it = 1;

    if (fdebug)
      printf("fuzzing_mask[%d]: %c\n", test_ptr, fuzzing_mask[test_ptr]);
    switch (fuzzing_mask[test_ptr]) {
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
          while (i < COUNT_FLAG && do_it) {
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
            memcpy((char *)&hdr->pkt[test_pos], (char *)&words[test_cnt - 1],
                   2);
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
      case 'D':
        intp = (unsigned int *)&pkt_bak[test_pos];
        if (test_cnt <= COUNT_DWORD) {
          if (*intp != dwords[test_cnt - 1])
            memcpy((char *)&hdr->pkt[test_pos], (char *)&dwords[test_cnt - 1],
                   4);
          else
            do_it = 0;
        } else {
          i = 0;
          while (i < COUNT_DWORD && do_it) {
            if (dwords[i] == *intp) do_it = 0;
            i++;
          }
          if (do_it) {
            i = *intp ^ xors[test_cnt - COUNT_DWORD - 1];
            intp = (unsigned int *)&hdr->pkt[test_pos];
            *intp = (unsigned int)i;
            //          *intp = (unsigned int) (i % 4294967295);
          }
        }
        if (test_cnt == COUNT_DWORD + COUNT_XOR) {
          test_cnt = 0;
          test_ptr++;
          test_pos += 4;
        }
        break;
      default:
        fprintf(stderr,
                "This character should not be in the fuzz string: %c(%d) "
                "position %d string %s\n",
                fuzzing_mask[test_ptr], fuzzing_mask[test_ptr], test_ptr,
                fuzzing_mask);
        return -1;
        break;
    }

    if (do_it && do_fuzz) {
      if (test_current >= test_start && test_current <= test_end && do_fuzz) {
        // Generate new transaction id
        if (xid == 0) {
          int three_byte_test_current = test_current % 0x1000000;

          memcpy(hdr->pkt + 63, (char *)&three_byte_test_current, 3);
        }
        // Regenerate UDP checksum
        hdr->pkt[60] = 0;
        hdr->pkt[61] = 0;
        i = checksum_pseudo_header(hdr->original_src, hdr->final_dst, NXT_UDP,
                                   &hdr->pkt[54], hdr->pkt_len - 54);
        hdr->pkt[60] = i / 256;
        hdr->pkt[61] = i % 256;

        // send packets
        int k;

        for (k = 0; k < no_send; k++) {
          if (fdebug) fprintf(stderr, "send it\n");
          while (thc_send_pkt(interface, pkt, pkt_len) < 0)
            usleep(1);
        }
        // printf(".");
        usleep(250);
        ++f_cnt;
      }
      // reset to basic packet
      memcpy(hdr->pkt, pkt_bak, hdr->pkt_len);
      test_current++;
    }
  }
  return 0;
}

void dhcpc_listener() {
  if ((s = thc_bind_udp_port(547)) < 0) {
    fprintf(stderr, "Error: could not bind to 547/udp\n");
    exit(-1);
  }
  if (thc_bind_multicast_to_socket(s, interface, thc_resolve6("ff02::1:2")) <
      0) {
    fprintf(stderr, "Error: could not bind multicast address\n");
    exit(-1);
  }
  if ((t = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
    perror("Error:");
    exit(-1);
  }

  if (p_cnt > 0) {
    printf("%d messages sent\n", p_cnt);
    p_cnt = 0;
  }
  printf(
      "\nListening for DHCPv6 clients on %s (Press Control-C to end) ...\n\n",
      interface);
  while (1) {
    memset((char *)&from, 0, sizeof(from));
    memset(&iov, 0, sizeof(iov));
    memset(&mhdr, 0, sizeof(mhdr));
    iov.iov_base = rdatabuf;
    iov.iov_len = sizeof(rdatabuf);
    mhdr.msg_name = &from;
    mhdr.msg_namelen = sizeof(from);
    mhdr.msg_iov = &iov;
    mhdr.msg_iovlen = 1;
    mhdr.msg_control = (caddr_t)cmsgbuf;
    mhdr.msg_controllen = sizeof(cmsgbuf);
    if ((len = recvmsg(s, &mhdr, 0)) > 0) {
      fromlen = mhdr.msg_namelen;
      if (fdebug) thc_dump_data(rdatabuf, len, "Received Packet");
      ddst.sin6_addr = ((struct sockaddr_in6 *)mhdr.msg_name)->sin6_addr;
      ptr2 = thc_ipv62notation((char *)&ddst.sin6_addr);
      printf("\nReceived DHCPv6 Type %d message from %s\n", rdatabuf[0], ptr2);
      strncpy((char *)&victim, ptr2, sizeof(victim));
      free(ptr2);
      dst = thc_resolve6(victim);
      /* get xid and cid */
      tribyte_id[2] = rdatabuf[1];
      tribyte_id[1] = rdatabuf[2];
      tribyte_id[0] = rdatabuf[3];
      printf("Transaction ID: %x%x%x\n", rdatabuf[1], rdatabuf[2], rdatabuf[3]);
      xid = 1;
      int roffset = 5;

      while (roffset < len) {
        if (rdatabuf[roffset] != 1) {
          /* skip option */
          if (fdebug)
            printf("%d option %d length %d\n", roffset, (int)rdatabuf[roffset],
                   (int)rdatabuf[roffset + 2]);
          roffset += (int)rdatabuf[roffset + 2];
          roffset += 4;
          continue;
        }
        if (rdatabuf[roffset + 4] != 1) {
          fprintf(stderr, "Can only reply to clients using DUID Type 1\n");
          break;
        }
        if (rdatabuf[roffset + 3] == 0x00 && rdatabuf[roffset + 4] == 0x01) {
          cidflag = 1;
          memcpy(cid, &rdatabuf[roffset + 3], 14);
          if (fdebug) printf("got it!\n");
          break;
        }
      }
      printf(
          "Client ID: "
          "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
          cid[0], cid[1], cid[2], cid[3], cid[4], cid[5], cid[6], cid[7],
          cid[8], cid[9], cid[10], cid[11], cid[12], cid[13]);
      if (oflg) printf("Options: %s\n", option_string);
      printf("\nFields Fuzzed:\n\n");
      do_fuzzer();
      printf(
          "\n\nListening for DHCPv6 clients on %s (Press Control-C to end) "
          "...\n\n",
          interface);
      f_cnt = 0;
    } /* Received */
  }   /* while */
}

int main(int argc, char *argv[]) {
  if (argc < 2 || strncmp(argv[1], "-h", 2) == 0) help(argv[0]);

  if (getenv("THC_IPV6_PPPOE") != NULL || getenv("THC_IPV6_6IN4") != NULL)
    printf("WARNING: %s is not working with injection!\n", argv[0]);

  // Parse options
  memset(cid, 0, 14); /* clear cid */
  while ((i = getopt(argc, argv, "123456789ABCDmn:t:e:T:dlp:frv:x:c:o:")) >=
         0) {
    switch (i) {
      case '1':
        do_type = DO_SOL;
        break;
      case '2':
        do_type = DO_ADV;
        break;
      case '3':
        do_type = DO_REQ;
        break;
      case '4':
        do_type = DO_CON;
        break;
      case '5':
        do_type = DO_REN;
        break;
      case '6':
        do_type = DO_REB;
        break;
      case '7':
        do_type = DO_REP;
        break;
      case '8':
        do_type = DO_REL;
        break;
      case '9':
        do_type = DO_DEC;
        break;
      case 'A':
        do_type = DO_REC;
        break;
      case 'B':
        do_type = DO_NFO;
        break;
      case 'C':
        do_type = DO_REL_FOR;
        break;
      case 'D':
        do_type = DO_REL_REP;
        break;
      case 'm':
        fuzz_dhcp_msg = 1;
        break;
      case 'n':
        no_send = atoi(optarg);
        break;
      case 't':
        test_start = atoi(optarg);
        break;
      case 'e':
        test_end = atoi(optarg);
        break;
      case 'T':
        test_end = test_start = atoi(optarg);
        break;
      case 'l':
        use_real_link = 0;  // no break
      case 'f':
        use_real_mac = 0;
        break;
      case 'p':
        ping = atoi(optarg);
        break;
      case 'd':
        fdebug = 1;
      case 'r':
        i = 0;
        break;  // just to ignore -r
      case 'v':
        strncpy((char *)&victim, optarg, sizeof(victim));
        listen_for_clients = 0;
        break;
      case 'o':
        oflg = 1;
        strncpy((char *)&option_string, optarg, sizeof(option_string));
        break;
      case 'x':
        sscanf(optarg, "%x", &xid);
        break;
      case 'c':
        cidflag = 1;
	unsigned int cidint[14];
        sscanf(optarg, "%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x",
                &cidint[0],  &cidint[1],  &cidint[2],
                &cidint[3],  &cidint[4],  &cidint[5],
                &cidint[6],  &cidint[7],  &cidint[8],
                &cidint[9],  &cidint[10], &cidint[11],
                &cidint[12], &cidint[13]);
	unsigned int i;
	for(i = 0; i < 14; i++) {
		cid[i] = (char) cidint[i];
	}
        break;
      default:
        fprintf(stderr, "Error: unknown option -%c\n", i);
        exit(-1);
    }
  }

  // Check options
  if (no_send < 1) {
    fprintf(stderr, "ERROR: -n number must be between one and 2 billion\n");
    exit(-1);
  }

  if (test_end < test_start) {
    printf("don't fuck up the command line options!\n");
    exit(-1);
  }

  memset(mac, 0, sizeof(mac));
  interface = argv[optind];
  if (interface == NULL) {
    fprintf(stderr, "interface required\n");
    exit(0);
  }
  if (use_real_link)
    src = thc_get_own_ipv6(interface, NULL, PREFER_LINK);
  else
    src = thc_resolve6("fe80::");
  if (use_real_mac) {
    mac6 = thc_get_own_mac(interface);
    memcpy(mac, mac6, sizeof(mac));
  }
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  if (listen_for_clients)
    dhcpc_listener();
  else
    dst = thc_resolve6(victim);

  // only to prevent our system to send icmp port unreachable messages
  if ((s = thc_bind_udp_port(547)) < 0)
    fprintf(stderr, "Warning: could not bind to 547/udp\n");
  if ((p = thc_pcap_init_promisc(interface, "ip6 and udp and dst port 547")) ==
      NULL) {
    fprintf(stderr, "Error: can not open interface %s in promisc mode\n",
            interface);
    exit(-1);
  }
  printf("\nVictim: %s\n", victim);
  if (xid) printf("Transaction ID: %x\n", xid);
  if (cidflag)
    printf(
        "Client ID: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
        cid[0], cid[1], cid[2], cid[3], cid[4], cid[5], cid[6], cid[7], cid[8],
        cid[9], cid[10], cid[11], cid[12], cid[13]);
  if (oflg) printf("Options: %s\n", option_string);
  printf("\nFields Fuzzed:\n\n");
  do_fuzzer();
}

int do_fuzzer() {
  char *ptr;

  int bad_length = 0;

  // Generate fuzzing mask and packet
  memset((char *)&fuzzing_mask, 0, 256); /* clear fuzzing mask */
  memset((char *)&wdatabuf, 0, 1024);    /* clear message buffer */

  strcat(fuzzing_mask, mac_fuzz);        /* Don't fuzz MAC */
  strcat(fuzzing_mask, ipv6_fuzz);       /* Don't fuzz target IPv6 address */
  strcat(fuzzing_mask, udp_header_fuzz); /* Don't fuzz UDP header */

  if (fuzz_dhcp_msg == 0) {
    options[0].code[0] = do_type;
    strcat(fuzzing_mask, options[0].dont_fuzz);
  } else
    strcat(fuzzing_mask, options[0].fuzz);
  wdatabuf[0] = options[0].code[0];
  // Transaction ID
  if (xid > 0) {
    if (listen_for_clients == 0) memcpy(tribyte_id, (char *)&xid, 3);
    options[1].code[0] = tribyte_id[2];
    options[1].code[1] = tribyte_id[1];
    options[1].code[2] = tribyte_id[0];
    strcat(fuzzing_mask, options[1].dont_fuzz);
  } else
    strcat(fuzzing_mask, options[1].fuzz);
  memcpy((char *)&wdatabuf[1], options[1].code, options[1].length);

  // Load client ID
  memcpy((char *)&options[2].code[4], cid, 14);
  if (cidflag == 0)
    strcat(fuzzing_mask, options[2].fuzz);
  else
    strcat(fuzzing_mask, options[2].dont_fuzz);
  memcpy((char *)&wdatabuf[4], options[2].code, options[2].length);

  // Insert time stamp and MAC in Server ID option
  double secs;

  secs = time(NULL);
  memcpy((char *)&options[3].code[8], (char *)&secs, 4); /* time stamp */
  memcpy((char *)&options[3].code[12], thc_get_own_mac(interface), 6);
  int optx = 0;
  int opt_off = 22;

  ptr = option_string;
  while (*ptr) {
    if (*ptr < 'a' || *ptr > 'r') {
      ++ptr;
      continue;
    }
    if (*ptr == 'L') {
      bad_length = 1;
      ++ptr;
      continue;
    }
    for (optx = 0; optx < 21; optx++)
      if (*ptr == options[optx].tag) break;
    if (bad_length) {
      options[optx].fuzz[2] = 'B';
      options[optx].fuzz[3] = 'B';
      bad_length = 0;
    }
    strcat(fuzzing_mask, options[optx].fuzz);

    memcpy((char *)&wdatabuf[opt_off], options[optx].code,
           options[optx].length);
    opt_off += options[optx].length;
    ++ptr;
  }
  if (fdebug) printf("%s\n", fuzzing_mask);

  if (!use_real_link)
    for (i = 0; i < 8; i++)
      src[i + 8] = rand() % 256;

  if (!use_real_mac) {
    mac[i * 2] = rand() % 256;
    mac[i * 2 + 1] = rand() % 256;
  }

  if ((pkt = thc_create_ipv6_extended(interface, PREFER_LINK, &pkt_len, src,
                                      dst, 1, 0, 0, 0, 0)) == NULL) {
    fprintf(stderr, "Can't create IPv6 Extended\n");
    return -1;
  }
  if (thc_add_udp(pkt, &pkt_len, 547, 546, 0, wdatabuf, opt_off) < 0) {
    fprintf(stderr, "Can't add UDP\n");
    return -1;
  }

  if (thc_generate_pkt(interface, mac6, NULL, pkt, &pkt_len) < 0) {
    fprintf(stderr, "Can't generate packet\n");
    return -1;
  }
  // Fuzz DHCPv6 Messgage and Send It
  if (fuzz_loop(pkt, &pkt_len) < 0) return -1;

  pkt = thc_destroy_packet(pkt);
  return 0;
}
