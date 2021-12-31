/*
 * Contributed by:
 *  Brandon Hutcheson, Graeme Neilson and Ryan Ko
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
#include <netinet/in.h>
#include <sys/select.h>
#include "thc-ipv6.h"

#define COUNT_FLAG 11
#define COUNT_BYTE 4
#define COUNT_WORD 16
#define COUNT_XOR 2
#define COUNT_EXTEND 256
#define COUNT_DWORD 256

#define NEVER 2000000000
#define TEST_MAX (NEVER - 1)

#define DO_SOL 1
#define DO_REQ 2
#define DO_CON 3
#define DO_REN 4
#define DO_REB 5
#define DO_DEC 6
#define DO_REL 7
#define DO_INF 8

#define STATELESS 0
#define STATEFULL 1

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
char fuzztype_ether[] = "..............";  // 14 byte header
char fuzztype_ip6[] =
    "........................................";  // 40 byte header
char fuzztype_udp[] = "........";                // 8 byte header
char fuzztype_dhcp6[] = "X...";    // 4 byte header (fuzz message type)
char fuzztype_dhcp6no[] = "....";  // 4 byte header (don't fuzz message type)

// OPTION HEADERS
char fuzztype_elapsed_time[] = "WWW";            // 6 byte header
char fuzztype_client_identifier[] = "WWWWDWWW";  // 18 byte header
char fuzztype_server_identifier[] = "WWWWDWWW";  // 18 byte header
char fuzztype_IA_NA[] = "WWDDD";                 // 16 byte header
char fuzztype_IA_Address[] = "WWXX..............DD";
char fuzztype_FQDN[] = "WWF";  // 5 byte header + length of domain string to be
                               // added in programatically
char fuzztype_option_request[] =
    "WWW";  // 6 byte header (add extra W for each additional option)
char fuzztype_prefixdele[] = "WWDDDWWDDFW............W";  // 45 bytes
char fuzztype_reconfig[] = "WW";                          // 4 bytes
char fuzztype_option_options[] = "WWWXXXXXXXXXXXXXX";     // 20 bytes
// //Matched solicit from RF manual
// char fuzztype_solicit[] = ".......FFFFFFFFF................BBBXXXX";
// //Still have to add in other types.
// char fuzztype_tran_id[] = "XF..WXBXX..............XX..............";
// char fuzztype_options[] = "........................................";

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
char solicit[] = {
    0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0x00, 0x29,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x1a, 0x00, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x06, 0x00,
    0x10, 0x00, 0x15, 0x00, 0x17, 0x00, 0x1f, 0x00, 0x38, 0x00, 0x40, 0x00,
    0x63, 0x00, 0x7b, 0x00, 0xc7};

int port = -1;

void help(char *prg) {
  printf("%s %s (c) 2022 by %s %s\n\n", prg, VERSION,
         "Brandon Hutcheson, Graeme Neilson and Ryan Ko", RESOURCE);
  printf(
      "Syntax: %s [-t number | -T number] [-e number | -T number] [-p number] "
      "[-md] [-1|-2|-3|-4|-5|-6|-7|-8] interface [domain-name]\n\n",
      prg);
  printf("Options:\n");
  printf(" -1         fuzz DHCPv6 Solicit (default)\n");
  printf(" -2         fuzz DHCPv6 Request\n");
  printf(" -3         fuzz DHCPv6 Confirm\n");
  printf(" -4         fuzz DHCPv6 Renew\n");
  printf(" -5         fuzz DHCPv6 Rebind\n");
  printf(" -6         fuzz DHCPv6 Release\n");
  printf(" -7         fuzz DHCPv6 Decline\n");
  printf(" -8         fuzz DHCPv6 Information Request\n");
  printf(" -m         fuzz the message type as well\n");
  printf(" -t number  continue from test no. number\n");
  printf(" -e number  continue to test no. number\n");
  printf(" -T number  only performs test no. number\n");
  printf(" -n number  how many times to send each packet (default: 1)\n");
  printf(" -f         spoof mac\n");
  printf(" -F         spoof link address\n");
  printf(" -w sec     wait number of seconds between packets (default: 0)\n");
  printf(
      " -p number  perform an alive check every number of tests (default: "
      "none)\n");
  printf(
      " -d         Use -d to force DNS updates, you can specify a domain name "
      "on the commandline.\n");
  printf("\nFuzzes a DHCPv6 packets to a server\n");
  printf("You can only define one of -0 ... -4 types, defaults to -1.\n");
  printf(
      "Returns -1 on error, 0 on tests done and targt alive or 1 on target "
      "crash.\n");
  exit(-1);
}

char  dnsupdate1[] = {0, 39, 0, 8, 1, 6, 122, 97, 97, 97, 97, 97};
char  dnsupdate2[] = {0, 6, 0, 2, 0, 39};
char  dns_option_hdr[256];
int   dns_option_hdr_len = 0, waittime = 0;
char  fuzzbuf[256];
char *interface = NULL, *dns_name = NULL, elapsed[6] = {0, 8, 0, 2, 0, 0};
int do_dns = 0, test_start = 0, test_end = TEST_MAX, ping = NEVER, no_send = 1,
    got_packet = 0;
pcap_t *p = NULL;
int     do_type = DO_SOL, fuzz_msg_type = 0;
int     timeout = 4;

void ignoreit(u_char *foo, const struct pcap_pkthdr *header,
              const unsigned char *data) {
  return;
}

int try_send_pkt(char *interface, char *pkt, int *pkt_len) {
  // Try send packet
  int    retry_send = 1;
  time_t start_time = time(NULL);
  while (time(NULL) - start_time < timeout && retry_send) {
    if (thc_send_pkt(interface, pkt, pkt_len) < 0)
      retry_send = 1;
    else
      retry_send = 0;
  }
  if (retry_send) {
    fprintf(
        stderr,
        "Timeout error: Unable to send check alive packet within timeout\n");
    exit(-1);
  }
  if (waittime > 0) sleep(waittime);
  return 0;
}

int check_alive(pcap_t *p) {
  int            ret = -2, len, pkt_len = 0, i;
  time_t         t;
  char           wdatabuf[1024];
  char *         pkt = NULL;
  unsigned char *dst = thc_resolve6("ff02::1:2");
  unsigned char *mac6 = thc_get_own_mac(interface);

  len = sizeof(solicit);
  memcpy(wdatabuf, solicit, len);
  // start0: 1-3 rand, 18-21 rand, 22-27 mac, 32-35 rand
  for (i = 0; i < 3; i++) {
    wdatabuf[i + 1] = rand() % 256;
    wdatabuf[i + 18] = rand() % 256;
    wdatabuf[i + 32] = rand() % 256;
  }
  memcpy(wdatabuf + 22, mac6, 6);

  if ((pkt = thc_create_ipv6_extended(interface, PREFER_LINK, &pkt_len, NULL,
                                      dst, 1, 0, 0, 0, 0)) == NULL) {
    fprintf(stderr,
            "Error: Failed to create check allive ivp6 packet header\n");
    exit(-1);
  }

  if (thc_add_udp(pkt, &pkt_len, 546, 547, 0, wdatabuf, len) < 0) {
    fprintf(stderr, "Error: Failed to create check allive udp packet header\n");
    exit(-1);
  }

  if (thc_generate_pkt(interface, mac6, NULL, pkt, &pkt_len) < 0) {
    fprintf(stderr, "Error: Failed to create check allive packet header\n");
    exit(-1);
  }

  // debug = 1;

  // Empty packet capture queue
  while (thc_pcap_check(p, (char *)ignoreit, NULL) > 0)
    ;

  // Send initial solicit request
  try_send_pkt(interface, pkt, &pkt_len);

  // Check for response in loop and timeout if we don't get one
  t = time(NULL);
  while (ret < 0) {
    // Got reply packet; server alive!
    if (thc_pcap_check(p, (char *)ignoreit, NULL) > 0) ret = 1;

    // If we still haven't received a packet after 1 second resend the solicit
    if (time(NULL) > t + 1 && ret == -2) {
      if (thc_send_pkt(interface, pkt, &pkt_len) <
          0) {  // Don't want to use try_send_pkt as it could take longer than
                // timeout
        usleep(75);
        thc_send_pkt(interface, pkt, &pkt_len);  // Retry sending packet after
                                                 // short time if sending failed
      }
      ret = -1;
    }

    // Fail after 4 seconds
    if (time(NULL) > t + timeout && ret < 0) ret = 0;
  }
  if (ret == 0) {
    fprintf(stderr,
            "Timeout: Failed to receive dhcp solicitation replay in check "
            "alive function within %d seconds\n",
            timeout);
  }

  // debug = 0;

  thc_destroy_packet(pkt);

  return ret > 0 ? 1 : 0;
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

  printf("Fuzzing packet, starting at fuzz case %d, ending at fuzz case %d:\n",
         test_start, test_end);
  printf("fuzzbuf(%lu): %s\n", strlen(fuzzbuf), fuzzbuf);
  while (do_fuzz) {
    if (test_cnt == 0)
      while (fuzzbuf[test_ptr] == '.') {
        test_ptr++;
        test_pos++;
      }

    if (fuzzbuf[test_ptr] == 0) do_fuzz = 0;

    test_cnt++;
    do_it = 1;

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
                "This character should not be in the fuzz string, shoot the "
                "programmer: %c(%d) position %d string %s\n",
                fuzzbuf[test_ptr], fuzzbuf[test_ptr], test_ptr, fuzzbuf);
        return -1;
        break;
    }

    if (do_it && do_fuzz) {
      if (test_current >= test_start && test_current <= test_end && do_fuzz) {
        printf("[%s] pos[%d]=%c -> %d | pkt[%d] | %d (%d=>%d)| \n",
               /*fuzzbuf*/ "", test_ptr, fuzzbuf[test_ptr], test_cnt, test_pos,
               test_current, test_start, test_end);

        // Generate new transaction id
        int three_byte_test_current = test_current % 0x1000000;
        memcpy(hdr->pkt + 63, (char *)&three_byte_test_current, 3);

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
          while (thc_send_pkt(interface, pkt, pkt_len) < 0)
            usleep(1);
          if (waittime) sleep(waittime);
        }
        // printf(".");
        usleep(250);

        // TODO: Server up check
        if ((test_current - test_start) % ping == 0 && test_current != 0 &&
            test_start != test_current)
          if (check_alive(p) == 0) {
            i = ((((test_current - test_start) / ping) - 1) * ping) +
                test_start + 1;
            printf(
                "\nResult: target %s crashed during fuzzing, offending test "
                "case no. could be %d to %d\n",
                thc_ipv62notation(hdr->final_dst), i < 0 ? 0 : i, test_current);
            exit(1);
          }
      }

      // reset to basic packet
      memcpy(hdr->pkt, pkt_bak, hdr->pkt_len);
      test_current++;
    }
  }
  return 0;
}

void construct_from_adv_and_fuzz(u_char *foo, const struct pcap_pkthdr *header,
                                 const unsigned char *data) {
  int            len = header->caplen, pkt_len = 0, mlen = 10, olen;
  unsigned char *ptr = (unsigned char *)data, *pkt = NULL;
  char *         smac, mac[6] = {0, 0x0d, 0, 0x0d, 0x0d, 0x0e};
  char           mybuf[1024] = {0x03, 0, 0, 0, 0, 8, 0, 2, 0, 0};
  int            done_dns = 0, i;

  // Begin fuzz buffer
  strcat(fuzzbuf, fuzztype_elapsed_time);

  // Set message type
  switch (do_type) {
    case DO_REQ:
      mybuf[0] = 0x03;
      break;
    case DO_CON:
      mybuf[0] = 0x04;
      break;
    case DO_REN:
      mybuf[0] = 0x05;
      break;
    case DO_REL:
      mybuf[0] = 0x08;
      break;
    case DO_DEC:
      mybuf[0] = 0x09;
      break;
    case DO_INF:
      mybuf[0] = 0x0B;
      break;
    default:
      fprintf(stderr, "Error: Unknown do type %d\n", do_type);
      exit(-1);
      break;
  }

  // Skip over header to dhcp header
  if (do_hdr_size) {
    data += do_hdr_size;
    len -= do_hdr_size;
    if ((data[0] & 240) != 0x60) return;
  } else {
    data += 14;
    len -= 14;
  }

  if (len < 126 || data[6] != NXT_UDP || data[48] != 2) return;

  data += 48;
  len -= 48;

  // Copy transaction id and skip to message options
  memcpy(mybuf + 1, data + 1, 3);
  data += 4;
  len -= 4;

  // Loop over options till reach end of header
  while (len >= 4) {
    // Set olen to the option length minus type and length fields and check for
    // bogus packet
    if ((olen = data[2] * 256 + data[3]) > len - 4 ||
        olen < 0) {  // the 4 here is the 4 bytes for the option type and option
                     // length fields
      printf("Information: evil packet received\n");
      olen = 0;
      len = -1;
    } else {
      // Copy server identifier or IA_NA to message
      if (data[1] > 1 && data[1] <= 3 && !(data[1] == 2 && do_type == DO_CON) &&
          !(data[1] == 3 &&
            do_type == DO_INF)) {  // skip copying server identifier for confirm
                                   // or IA_NA for information request messages
        memcpy(mybuf + mlen, data, olen + 4);
        mlen += olen + 4;

        // Append server identifier fuzzing
        if (data[1] == 2) strcat(fuzzbuf, fuzztype_server_identifier);
        // Append IA_NA fuzzing + IA Address fuzzing
        else if (data[1] == 3) {
          strcat(fuzzbuf, fuzztype_IA_NA);
          if (olen > 12) strcat(fuzzbuf, fuzztype_IA_Address);
        }
        // printf("buf(%d): %s\n", strlen(fuzzbuf), fuzzbuf);
      }
      // Copy client identifier to message
      else if (data[1] == 1) {
        memcpy(mybuf + mlen, data, olen + 4);
        mlen += olen + 4;
        // smac auf client mac in paket setzen
        if (olen == 14)
          smac = (char *)(data + 12);
        else
          smac = mac;

        // Append client identifier fuzzing
        strcat(fuzzbuf, fuzztype_client_identifier);
        // printf("buf(%d): %s\n", strlen(fuzzbuf), fuzzbuf);
      }
      // Copy dns option
      else if (data[1] == 39 && do_dns) {
        memcpy(mybuf + mlen, data, olen + 4);
        mybuf[mlen + 4] = 1;  // force server to write dns entry
        mlen += olen + 4;

        // Append dns fuzzing
        strcat(fuzzbuf, fuzztype_FQDN);
        for (i = 0; i < olen - 1; ++i)
          strcat(fuzzbuf, "B");  // Fuzz the domain name string
        strcat(fuzzbuf, fuzztype_option_request);
        // printf("buf(%d): %s\n", strlen(fuzzbuf), fuzzbuf);

        // Make sure we don't add dns twice
        done_dns = 1;
      }
      data += olen + 4;
      len -= olen + 4;
      if (len < 0) {
        printf("Information: evil packet received\n");
        len = -1;
      }
    }
  }

  // Add saved dns option onto this packet
  if (do_dns && !done_dns) {
    memcpy(mybuf + mlen, dns_option_hdr, dns_option_hdr_len);
    mlen += dns_option_hdr_len;

    // Append dns fuzzing
    olen = dns_option_hdr[2] * 256 + dns_option_hdr[3];
    strcat(fuzzbuf, fuzztype_FQDN);
    for (i = 0; i < olen - 1; ++i)
      strcat(fuzzbuf, "B");  // Fuzz the domain name string
    strcat(fuzzbuf, fuzztype_option_request);
    // printf("buf(%d): %s\n", strlen(fuzzbuf), fuzzbuf);
  }

  // Build and send fuzzed message packets
  if (len >= 0) {
    unsigned char *dst = thc_resolve6("ff02::1:2");

    if ((pkt = thc_create_ipv6_extended(interface, PREFER_LINK, &pkt_len,
                                        ptr + 38, dst, 1, 0, 0, 0, 0)) ==
        NULL) {
      fprintf(stderr, "Error: Couldn't create dhcp requests ipv6 header\n");
      exit(-1);
    }

    if (thc_add_udp(pkt, &pkt_len, 546, 547, 0, mybuf, mlen) < 0) {
      fprintf(stderr, "Error: Couldn't create dhcp requests udp header\n");
      exit(-1);
    }

    if (thc_generate_pkt(interface, smac, ptr + 6, pkt, &pkt_len) < 0) {
      fprintf(stderr, "Error: Couldn't create dhcp requests ethernet header\n");
      exit(-1);
    }

    if (fuzz_loop(pkt, &pkt_len) < 0) {
      fprintf(stderr, "Error: Fuzzing request packet failed\n");
      exit(-1);
    } else {
      got_packet = 1;  // Used to suppress timeout error
    }

    pkt = thc_destroy_packet(pkt);
  }

  // Truncate the fuzz buffer back to it's original length
  fuzzbuf[66] = 0;
  // printf("Trunc fuzzbuf: %s\n", fuzzbuf);
}

int main(int argc, char *argv[]) {
  char mac[6] = {0, 0x0c, 0, 0, 0, 0}, *pkt = NULL;
  // defines mac as 6 pieces and defines pkt as null.
  char wdatabuf[1024];
  // builds data buffer and sets memory size at 1024mb
  unsigned char *mac6 = mac, *src, *dst;
  // creates mac6 address usuing
  int i, s, len, pkt_len = 0, dlen = 0;
  int do_all = 1, use_real_mac = 1, use_real_link = 1;
  int state;

  if (argc < 2 || strncmp(argv[1], "-h", 2) == 0) help(argv[0]);

  if (getenv("THC_IPV6_PPPOE") != NULL || getenv("THC_IPV6_6IN4") != NULL)
    printf("WARNING: %s is not working with injection!\n", argv[0]);

  // Parse options
  while ((i = getopt(argc, argv, "123456789mn:t:e:T:dFp:frw:")) >= 0) {
    switch (i) {
      case 'w':
        waittime = atoi(optarg);
        break;
      case '1':
        do_type = DO_SOL;
        break;
      case '2':
        do_type = DO_REQ;
        break;
      case '3':
        do_type = DO_CON;
        break;
      case '4':
        do_type = DO_REN;
        break;
      case '5':
        do_type = DO_REB;
        break;
      case '6':
        do_type = DO_REL;
        break;
      case '7':
        do_type = DO_DEC;
        break;
      case '8':
        do_type = DO_INF;
        break;
      case 'm':
        fuzz_msg_type = 1;
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
      case 'F':
        use_real_link = 0;  // no break
      case 'f':
        use_real_mac = 0;
        break;
      case 'p':
        ping = atoi(optarg);
        break;
      case 'd':
        do_dns = 1;
        break;
      case 'r':
        i = 0;
        break;  // just to ignore -r
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
  dns_name = argv[optind + 1];
  if (use_real_link)
    src = thc_get_own_ipv6(interface, NULL, PREFER_LINK);
  else
    src = thc_resolve6("fe80::");
  if (use_real_mac) {
    mac6 = thc_get_own_mac(interface);
    memcpy(mac, mac6, sizeof(mac));
  }
  dst = thc_resolve6("ff02::1:2");
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

  // Establish state
  if (do_type == DO_SOL || do_type == DO_REB)
    state = STATELESS;
  else
    state = STATEFULL;

  // generate full fuzz mask for stateless types and partial for statefull types
  strcpy(fuzzbuf, fuzztype_ether);
  strcat(fuzzbuf, fuzztype_ip6);
  strcat(fuzzbuf, fuzztype_udp);
  if (fuzz_msg_type)
    strcat(fuzzbuf, fuzztype_dhcp6);
  else
    strcat(fuzzbuf, fuzztype_dhcp6no);
  if (state == STATELESS) {
    strcat(fuzzbuf, fuzztype_elapsed_time);
    strcat(fuzzbuf, fuzztype_client_identifier);
    strcat(fuzzbuf, fuzztype_IA_NA);
    strcat(fuzzbuf, fuzztype_prefixdele);
    strcat(fuzzbuf, fuzztype_reconfig);
    strcat(fuzzbuf, fuzztype_option_options);
    if (do_dns) strcat(fuzzbuf, fuzztype_FQDN);
  }

  /** Generate packet **/
  len = sizeof(solicit);
  memcpy(wdatabuf, solicit, len);
  // printf("%d : %s\n", len, fuzzbuf);

  // Add dns option
  if (do_dns) {
    memcpy(wdatabuf + len, dnsupdate1, sizeof(dnsupdate1));
    memcpy(dns_option_hdr + dns_option_hdr_len, dnsupdate1, sizeof(dnsupdate1));
    dlen = len + 8;
    len += sizeof(dnsupdate1);
    dns_option_hdr_len += sizeof(dnsupdate1);

    // Append domain string prefix fuzz mask
    if (state == STATELESS) {  //<-- Do fuzzbuffer later
      for (i = 0; i < 7; ++i)  // 7 == Length of hard coded domain prefix
        strcat(fuzzbuf, "B");
    }

    if (dns_name != NULL && strlen(dns_name) < 240) {
      if (dns_name[0] != '.') {
        wdatabuf[len] = '.';
        wdatabuf[dlen - 5]++;
        wdatabuf[dlen - 3]++;
        len++;
      }
      memcpy(wdatabuf + len, dns_name, strlen(dns_name) + 1);
      memcpy(dns_option_hdr + dns_option_hdr_len, dns_name,
             strlen(dns_name) + 1);
      wdatabuf[dlen - 5] += strlen(dns_name) + 1;
      wdatabuf[dlen - 3] += strlen(dns_name) + 1;
      len += strlen(dns_name) + 1;
      dns_option_hdr_len += strlen(dns_name) + 1;

      // Append variable length domain string suffix fuzz mask
      if (state == STATELESS) {
        for (i = 0; i < strlen(dns_name) + 1; ++i)
          strcat(fuzzbuf, "B");
      }
    }
    memcpy(wdatabuf + len, dnsupdate2, sizeof(dnsupdate2));
    memcpy(dns_option_hdr + dns_option_hdr_len, dnsupdate2, sizeof(dnsupdate2));
    len += sizeof(dnsupdate2);
    dns_option_hdr_len += sizeof(dnsupdate2);

    // Append option request (FQDN request) fuzz mask
    if (state == STATELESS) { strcat(fuzzbuf, fuzztype_option_request); }
  }

  // Set message type
  if (state == STATELESS) {
    switch (do_type) {
      case DO_SOL:
        wdatabuf[0] = 0x01;
        break;
      case DO_REB:
        wdatabuf[0] = 0x06;
        break;
      default:
        break;
    }
  }

  // random src mac
  if (!use_real_link)
    for (i = 0; i < 8; i++)
      src[i + 8] = rand() % 256;

  // start0: 1-3 rand, 18-21 rand, 22-27 mac, 32-35 rand
  for (i = 0; i < 3; i++) {
    wdatabuf[i + 1] = rand() % 256;
    wdatabuf[i + 18] = rand() % 256;
    wdatabuf[i + 32] = rand() % 256;
    if (!use_real_mac) {
      mac[i * 2] = rand() % 256;
      mac[i * 2 + 1] = rand() % 256;
    }
    if (do_dns) wdatabuf[i + dlen] = 'a' + rand() % 26;
  }
  memcpy(wdatabuf + 22, mac, 6);

  if ((pkt = thc_create_ipv6_extended(interface, PREFER_LINK, &pkt_len, src,
                                      dst, 1, 0, 0, 0, 0)) == NULL)
    return -1;
  if (thc_add_udp(pkt, &pkt_len, 546, 547, 0, wdatabuf, len) < 0) return -1;

  if (thc_generate_pkt(interface, mac6, NULL, pkt, &pkt_len) < 0) return -1;

  // Fuzz solicit packet
  if (state == STATELESS) {
    if (fuzz_loop(pkt, &pkt_len) < 0) return -1;
  }

  // Fuzz request, confirm or renew paket
  else if (state == STATEFULL) {
    // Send a dhcp solicit to discover dhcpv6 servers
    if (thc_send_pkt(interface, pkt, &pkt_len) < 0) {
      fprintf(stderr, "Error: Failed to send initial solicit packet\n");
      return -1;
    }

    usleep(75);  //<-- I don't really know why this is neccessary but it seems
                 //to be

    // Construct and fuzz packets using server identifier
    got_packet = 0;
    time_t start_time = time(NULL);
    while (time(NULL) - start_time < timeout) {
      while (thc_pcap_check(p, (char *)construct_from_adv_and_fuzz, NULL) > 0)
        ;  // got_packet set in callback function
      if (got_packet) break;
    }
    if (!got_packet)
      fprintf(stderr,
              "Timeout: Didn't receive solicited advertisement packet within "
              "timeout. Is server down?\n");
  }

  pkt = thc_destroy_packet(pkt);

  // printf("fuzzbuf: %s\n", fuzzbuf);

  return 0;
}
