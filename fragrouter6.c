#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <poll.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>

#include "thc-ipv6.h"
#include "fragrouter6.h"

#ifndef POLLRDHUP
  #define POLLRDHUP 0
#endif

struct application_config {
  log_level_enum log_level;
  int buffer_size;
  unsigned short queue_number;
  nfq_callback *queue_callback;
};

extern int debug;
extern int do_pppoe;
extern int do_hdr_off;
extern int do_6in4;
extern int do_hdr_vlan;

struct application_config config;
int exit_from_loop = 0, verbose = 0, mtu = -1;
int minifrag = 8, evade_hop = 0, target_hop = 0;
unsigned int method = 0;
char *interface = NULL, ether[8];

void help(char *prg) {
  printf("fragrouter6 %s (c) 2016 by %s %s\n\n", VERSION, AUTHOR, RESOURCE);
  printf("Syntax: %s [-dv -f len -e count -t count] INTERFACE EVASION-METHOD\n\n", prg);
  printf("Options:\n");
  printf("  -f len    size of mini fragments (option 64, default %d)\n", minifrag);
  printf("  -e count  hop count to the IDS for evading (option 256 & 512)\n");
  printf("  -t count  hop count to the target that reachs it\n");
//  printf("  -d        debug mode for the thc-ipv6 library\n");
  printf("  -v        verbose mode, print all packets processed for evasion\n");
  printf("Evasion Methods:\n");
  printf("  0     no manipulation\n");
  printf("  1-31  the number of atomic fragmentation headers to insert\n");
  printf("  32    use destination headers for 1-31 instead of fragmentation headers\n");
  printf("  64    fragment each packet to %d byte length pieces (or change with -f)\n", minifrag);
  printf("  128   a large destination header that fragments the packet\n");
  printf("  256   insert fake TCP data with a hop count just for the IDS (-e)\n");
  printf("  512   insert TCP connection reset packet with a hop count just to the IDS (-e)\n");
  printf(" 1024   insert fake fragmentation data with a hop count just for the IDS (-e)\n");
  printf(" 2048   insert faked seq/ack data TCP packet\n");
  printf("\n");
  printf("Performs NIDS/NIPS evasion to all defined packets that originate from your\nsystem or pass through it. ");
  printf("All evasion methods can be combined (add together)\nwith the exception that only either one of 64 or 128 can be used at once.\nOption 1024 can be used with 1..31 and 64. ");
  printf("The evasion methods are processed in the following order: 256, 512, 2048, 1..31/33..63 then either 64 or 128 then 1024.\n");
  printf("Requires to set up ip6table rules that jump to NFQUEUE, use fragrouter6.sh\nwhich is a wrapper for ip6tables and fragrouter6!\n");
  exit(0);
}

void log_message(log_level_enum log_level, char *message, ...) {
  FILE *os = log_level == LOG_ERROR ? stderr : stdout;
  int error_number = errno;

  if (log_level < config.log_level) {
    return;
  }
  // Check if message is null to put only a new line
  if (message == NULL) {
    fprintf(os, "\n");
    return;
  }
  // Initialize dynamic argument list
  va_list ap;
  va_start(ap, message);
  vfprintf(os, message, ap);
  fprintf(os, "\n");
  // Check if error_number is non zero and log_level is LOG_ERROR;
  if (log_level == LOG_ERROR && error_number != 0) {
    fprintf(os, "Error %d: %s\n", error_number, strerror(error_number));
  }
  va_end(ap);
}

// Return values:  == 0 => ok, >0 => soft error, <0 => hard error
int netfilter_queue_callback(struct nfq_q_handle *hq, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *data) {
  unsigned int len, id, temp_id;
  unsigned char *packet, payload[2048], buf[2048], *dstmac;
  struct ip6_hdr *packet_header;
  char ip_addr_source[INET6_ADDRSTRLEN], ip_addr_destination[INET6_ADDRSTRLEN];
  int i, j, k, proto, drop = 0, buflen = 0;
  thc_ipv6_hdr hdr;
//  int differ = 0

  // Get packet header
  struct nfqnl_msg_packet_hdr *hp = nfq_get_msg_packet_hdr(nfad);

  // Check for null pointer
  if (hp != NULL) {
    // Get packet id
    id = ntohl(hp->packet_id);

    if (verbose)
      log_message(LOG_DEBUG, "Packet received: %u", id);

    // Get payload and ip header
    len = nfq_get_payload(nfad, (unsigned char **) &packet);
    packet_header = (struct ip6_hdr *) packet;
    proto = packet_header->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    
    // packet we generated raw? class value of 1
    if ((packet[1] & 240) == 16) {
      packet[1] = packet[1] & 15;
      nfq_set_verdict(hq, id, NF_ACCEPT, len, packet);
      if (verbose)
        log_message(LOG_DEBUG, "Own generated packet passed on.\n");
    }

    if (verbose) {
      // Get source and destination addresses (IP)
      inet_ntop(AF_INET6, &packet_header->ip6_src, ip_addr_source, INET6_ADDRSTRLEN);
      inet_ntop(AF_INET6, &packet_header->ip6_dst, ip_addr_destination, INET6_ADDRSTRLEN);
      log_message(LOG_DEBUG, "     Packet Length: %u", len);
      log_message(LOG_DEBUG, "    Payload Length: %u", htons(packet_header->ip6_ctlun.ip6_un1.ip6_un1_plen));
      log_message(LOG_DEBUG, "         Hop Count: %u", packet_header->ip6_ctlun.ip6_un1.ip6_un1_hlim);
      // Print out ip packet protocol
      switch (proto) {
      case IP_PROTOCOL_ICMP6:
        log_message(LOG_DEBUG, "          Protocol: ICMPv6");
        break;
      case IP_PROTOCOL_ICMP:
        log_message(LOG_DEBUG, "          Protocol: ICMP (1)");
        break;
      case IP_PROTOCOL_IGMP:
        log_message(LOG_DEBUG, "          Protocol: IGMP (2)");
        break;
      case IP_PROTOCOL_TCP:
        log_message(LOG_DEBUG, "          Protocol: TCP (6)");
        break;
      case IP_PROTOCOL_UDP:
        log_message(LOG_DEBUG, "          Protocol: UDP (17)");
        break;
      default:
        log_message(LOG_DEBUG, "          Protocol: UNKNOWN (%d)", packet_header->ip6_ctlun.ip6_un1.ip6_un1_nxt);
        break;
      }
      // Print out source and destination ip
      log_message(LOG_DEBUG, "         Source IP: %s", ip_addr_source);
      log_message(LOG_DEBUG, "    Destination IP: %s", ip_addr_destination);
      // Check hook type
      switch (hp->hook) {
        // Preliminary checks (checksum)
      case NF_IP_PRE_ROUTING:
        log_message(LOG_DEBUG, "              Hook: packet received from the box (PRE ROUTING)");
        break;
        // If the packet is for the current box
      case NF_IP_LOCAL_IN:
        log_message(LOG_DEBUG, "              Hook: packet is for the box (LOCAL INPUT)");
        break;
        // If the packet is for another interface
      case NF_IP_FORWARD:
        log_message(LOG_DEBUG, "              Hook: packet is for another interface (FORWARD)");
        break;
        // If the packet come from a process
      case NF_IP_LOCAL_OUT:
        log_message(LOG_DEBUG, "              Hook: packet come from the box (LOCAL OUT)");
        break;
        // Packet is ready to hit the wire
      case NF_IP_POST_ROUTING:
        log_message(LOG_DEBUG, "              Hook: packet is going out (POST ROUTING)");
        break;
        // This is impossible, but cover it isin't give more security!
      default:
        log_message(LOG_WARNING, "              Hook: unknown hook passed by netfilter (%d)", hp->hook);
        break;
      }

    }


    // Manipulate the packet
    if (len >= 48 && method > 0 && method != 32 && method != 1024) {
      temp_id = id << 8;
      hdr.pkt = buf;
      
      memcpy(payload, packet, len);
      if (target_hop > 0)
        payload[7] = target_hop;

      // correct order:  256, 512, 2048, 1..31, 64 | 128, 1024

      // Fake TCP Data Hop Count insertion
      if ((method & 256) == 256) { // check if its TCP with data
        i = 0;
        j = 40;
        if (payload[6] == NXT_TCP)
          i = 40;
        else {
          while (i == 0 && len > j + 8 && (payload[j] == NXT_DST || payload[j] == NXT_HBH || payload[j] == NXT_FRAG || payload[j] == NXT_ROUTE))
            j += (payload[j + 1] + 1) * 8;
          if (len > j + 8 && payload[j] == NXT_TCP) {
            j += (payload[j + 1] + 1) * 8;
            if (len > j + 20)
              i = j;
          }
        }
        
        if (i >= 40 && len > i + 20 && len > i + (payload[i + 12] >> 2)) {
          // OK, it is TCP and it has data!
          if ((dstmac = thc_get_mac(interface, NULL, payload + 24)) != NULL) {
            memcpy(buf, dstmac, 6); // create 2nd packet
            memcpy(buf + 6, ether, 8);
            memcpy(buf + 14, payload, len);
            buf[14 + 7] = evade_hop;
            k = len - i - (payload[i + 12] >> 2); // TCP data size
//printf("k = len %d - i %d - payload[i+12] >> 2 %d\n", len, i, (payload[i + 12] >> 2));
//printf("i %d + k %d\n", i, k);
            for (j = 0; j < k; j++) 
              buf[14 + len - k + j] = 'X'; // future: random
            buf[14 + i + 16] = 0; // reset checksum
            buf[14 + i + 17] = 0;
            j = checksum_pseudo_header(payload + 8, payload + 24, NXT_TCP, buf + 14 + i, len - i);
            buf[14 + i + 16] = j / 256; // set new TCP checksum
            buf[14 + i + 17] = j % 256;
            buflen = 14 + len;
            hdr.pkt_len = buflen;
            thc_send_pkt(interface, (unsigned char *)&hdr, &buflen); // send packet
          } else {
            dstmac = thc_ipv62notation(payload + 24);
            fprintf(stderr, "Error: could not get an Ethernet address to destination %s, dropping packet :-(\n", dstmac);
            drop = 1;
          }
          free(dstmac);
        }
      }

      // Connection reset spoofing and hop count adaption
      if ((method & 512) == 512) {
        i = 0;
        j = 40;
        if (payload[6] == NXT_TCP)
          i = 40;
        else {
          while (i == 0 && len > j + 8 && (payload[j] == NXT_DST || payload[j] == NXT_HBH || payload[j] == NXT_FRAG || payload[j] == NXT_ROUTE))
            j += (payload[j + 1] + 1) * 8;
          if (len > j + 8 && payload[j] == NXT_TCP) {
            j += (payload[j + 1] + 1) * 8;
            if (len > j + 20)
              i = j;
          }
        }

        if (i >= 40 && len >= i + 20 && payload[i + 13] != TCP_SYN) {
          // OK, it is TCP and it is not the initial SYN packet!
          if ((dstmac = thc_get_mac(interface, NULL, payload + 24)) != NULL) {
            memcpy(buf, dstmac, 6); // create 2nd packet
            memcpy(buf + 6, ether, 8);
            memcpy(buf + 14, payload, i + 20);
            buf[14 + 4] = 0;
            buf[14 + 5] = 20; // payload size = 20
            buf[14 + 7] = evade_hop;
            buf[14 + i + 12] = 0x50; // tcp hdr size = 20
            buf[14 + i + 13] = TCP_RST;
            memset(buf + 14 + i + 14, 0, 6); // reset checksum, window+urg ptr
            j = checksum_pseudo_header(payload + 8, payload + 24, NXT_TCP, buf + 14 + i, 20);
            buf[14 + i + 16] = j / 256; // set new TCP checksum
            buf[14 + i + 17] = j % 256;
            buflen = 14 + 40 + 20;
            hdr.pkt_len = buflen;
            thc_send_pkt(interface, (unsigned char *)&hdr, &buflen); // send packet
          } else {
            dstmac = thc_ipv62notation(payload + 24);
            fprintf(stderr, "Error: could not get an Ethernet address to destination %s, dropping packet :-(\n", dstmac);
            drop = 1;
          }
          free(dstmac);
        }
      }
      
      // Connection reset spoofing and hop count adaption
      if ((method & 2048) == 2048) {
        i = 0;
        j = 40;
        if (payload[6] == NXT_TCP)
          i = 40;
        else {
          while (i == 0 && len > j + 8 && (payload[j] == NXT_DST || payload[j] == NXT_HBH || payload[j] == NXT_FRAG || payload[j] == NXT_ROUTE))
            j += (payload[j + 1] + 1) * 8;
          if (len > j + 8 && payload[j] == NXT_TCP) {
            j += (payload[j + 1] + 1) * 8;
            if (len > j + 20)
              i = j;
          }
        }

        // send fake seq / ack values
        if (i >= 40 && len >= i + 20 && payload[i + 13] != TCP_SYN) {
          // OK, it is TCP and it is not the initial SYN packet!
          if ((dstmac = thc_get_mac(interface, NULL, payload + 24)) != NULL) {
            memcpy(buf, dstmac, 6); // create 2nd packet
            memcpy(buf + 6, ether, 8);
            memcpy(buf + 14, payload, len);
            // seq
            if ((unsigned char) buf[14 + i + 7] < 240)
              buf[14 + i + 7] += 16;
            else if ((unsigned char) buf[14 + i + 6] < 255) {
              buf[14 + i + 6]++;
              buf[14 + i + 7] = 0;
            } else if ((unsigned char) buf[14 + i + 5] < 255) {
              buf[14 + i + 5]++;
              memset(buf + 14 + i + 6, 0, 2);
            } else if ((unsigned char) buf[14 + i + 4] < 255) {
              buf[14 + i + 5]++;
              memset(buf + 14 + i + 5, 0, 3);
            } else
              memset(buf + 14 + i + 4, 0, 4);
            // ack
            if ((unsigned char) buf[14 + i + 11] < 240)
              buf[14 + i + 11] += 16;
            else if ((unsigned char) buf[14 + i + 10] < 255) {
              buf[14 + i + 10]++;
              buf[14 + i + 11] = 0;
            } else if ((unsigned char) buf[14 + i + 9] < 255) {
              buf[14 + i + 9]++;
              memset(buf + 14 + i + 10, 0, 2);
            } else if ((unsigned char) buf[14 + i + 8] < 255) {
              buf[14 + i + 9]++;
              memset(buf + 14 + i + 9, 0, 3);
            } else
              memset(buf + 14 + i + 8, 0, 4);

            // we only fix the checksum if we have evading set
            if (evade_hop) {
              buf[14 + 7] = evade_hop;
              memset(buf + 14 + i + 14, 0, 6); // reset checksum, window+urg ptr
              j = checksum_pseudo_header(buf + 14 + 8, buf + 14 + 24, NXT_TCP, buf + 14 + i, len - i);
              buf[14 + i + 16] = j / 256; // set new TCP checksum
              buf[14 + i + 17] = j % 256;
            }
            buflen = 14 + len;
            hdr.pkt_len = buflen;
            thc_send_pkt(interface, (unsigned char *)&hdr, &buflen); // send packet
          } else {
            dstmac = thc_ipv62notation(payload + 24);
            fprintf(stderr, "Error: could not get an Ethernet address to destination %s, dropping packet :-(\n", dstmac);
            drop = 1;
          }
          free(dstmac);
        }
      }
      
      // 1..31 atomic fragmentation headers
      if ((method & 31) > 0) {
        int proto_tmp;
        j = (method & 31);
        if ((method & 32) == 0)
          proto_tmp = IP_PROTOCOL_FRAG;
        else
          proto_tmp = IP_PROTOCOL_EH_DST;
        memcpy(buf, payload, 40);
        memset(buf + 40, 0, j * 8);
        memcpy(buf + 40 + j * 8, payload + 40, len - 40);
        for (i = 0; i < j; i++) {
          ++temp_id;
          if (temp_id % 64 == 0)
            ++temp_id;
          buf[40 + i * 8] = proto_tmp;
          if ((method & 32) == 0)
            memcpy(buf + 40 + i * 8 + 4, (char*)&temp_id, 4);
          else {
            buf[40 + i * 8 + 2] = temp_id % 64;
            buf[40 + i * 8 + 3] = 4;
          }
        }
        buf[40 + (j - 1) * 8] = proto;
        len += j * 8;
        // fix ipv6 header
        buf[4] = (len - 40) / 256;
        buf[5] = (len - 40) % 256;
        buf[6] = proto_tmp;
        // set new payload header
        memcpy(payload, buf, len);
        proto = proto_tmp;
      }
      
      // 1240 byte DST EH
      if ((method & 128) == 128) {
        ++temp_id;
        int rhdrsize = 8 + ( (method & 31) * 8 );
        int dhdrsize = (((1240 - rhdrsize) / 8) * 8);
        if ((dstmac = thc_get_mac(interface, NULL, payload + 24)) != NULL) {
          memset(buf, 0, sizeof(buf));
          memcpy(buf, dstmac, 6);
          memcpy(buf + 6, ether, 8);
          memcpy(buf + 14, payload, 40);
//          buf[14 + 1] = 16 + (payload[1] & 15); // set class == 1
          buf[14 + 6] = IP_PROTOCOL_FRAG;
          if (target_hop > 0)
            buf[14 + 7] = target_hop;
          buf[14 + 4] = (dhdrsize + 8) / 256; // packet length
          buf[14 + 5] = (dhdrsize + 8) % 256; // packet length (1240)
          buf[14 + 40] = IP_PROTOCOL_EH_DST;
          memset(buf + 14 + 41, 0, dhdrsize);
          buf[14 + 40 + 3] = 1;
          memcpy(buf + 14 + 40 + 4, (char*) &temp_id, 4);
          buf[14 + 40 + 8] = proto; // nxt header
          buf[14 + 40 + 9] = (dhdrsize / 8); // dhdrsize + 8, we send dhdrsize in this part
          buflen = 14 + 40 + rhdrsize + dhdrsize;
          hdr.pkt_len = buflen;
          thc_send_pkt(interface, (unsigned char *)&hdr, &buflen);

          memcpy(buf, payload, 40);
          memset(buf + 40, 0, 16);
          memcpy(buf + 40 + 16, payload + 40, len - 40);
          buf[40] = IP_PROTOCOL_EH_DST;
          buf[42] = dhdrsize / 256; // offset
          buf[43] = (dhdrsize % 256); // offset, no more frags
          memcpy(buf + 44, (char*)&temp_id, 4);
          len += 16;
          // fix ipv6 header
          buf[6] = IP_PROTOCOL_FRAG;
          buf[4] = (len - 40) / 256;
          buf[5] = (len - 40) % 256;
          buf[6] = IP_PROTOCOL_FRAG;
          // set new payload header
          memcpy(payload, buf, len);
        } else {
          dstmac = thc_ipv62notation(payload + 24);
          fprintf(stderr, "Error: could not get an Ethernet address to destination %s, dropping packet :-(\n", dstmac);
          drop = 1;
        }
        free(dstmac);
      }

      // Mini fragmentation mode (but only if the payload is larger than
      // the minifrag)
      if (minifrag + 40 < len && (method & 64) == 64) {
        // neue frag pakete generieren
        // neue pakete schicken
        // minifrag = 8
        int tmp_hop, tmp_minifrag = minifrag;
        drop = 1;
        ++temp_id;
        i = (method & 31);
        if (i > 0 && proto == IP_PROTOCOL_FRAG)
          tmp_minifrag += i*8;
        j = tmp_minifrag + 8;
        if ((dstmac = thc_get_mac(interface, NULL, payload + 24)) != NULL) {
          memcpy(buf, dstmac, 6);
          memcpy(buf + 6, ether, 8);
          memcpy(buf + 14, payload, 40);
//          buf[14 + 1] = 16 + (payload[1] & 15); // set class == 1
          buf[14 + 6] = IP_PROTOCOL_FRAG;
          if (target_hop > 0)
            buf[14 + 7] = target_hop;
          memset(buf + 14 + 40, 0, 8);
          buf[14 + 40] = proto;
          memcpy(buf + 14 + 40 + 4, (char*) &temp_id, 4);
          buf[14 + 4] = j / 256;
          buf[14 + 5] = j % 256;
          k = ((len - 40) / tmp_minifrag);
          if ((len - 40) % tmp_minifrag > 0)
            k++;
/*
printf("%d: \n", len);
for (debug = 0; debug < len; debug++) {
 if (debug % 16 == 0) printf("%d:", debug);
 if (debug == 40)printf("\n");
 printf("%02x", (unsigned char)payload[debug]);
 if (debug % 16 == 15) printf("\n");
}printf("\n");debug=0;
printf("tmp_minifrag: %d\n", tmp_minifrag);
printf("X %02x\n", payload[40 + 15 + 16]);
*/
          tmp_hop = buf[14 + 7];
          for (i = 1; i <= k; i++) {
            if (i == k && (len - 40) % tmp_minifrag > 0) {
              j = 8 + ((len - 40) % tmp_minifrag);
//printf("last j: 8 + (%d - 40 %% %d) = %d\n", len, tmp_minifrag, j);
              buf[14 + 4] = j / 256;
              buf[14 + 5] = j % 256;
            }
            buf[14 + 40 + 2] = ((i - 1) * tmp_minifrag) / 256;
            buf[14 + 40 + 3] = ((i - 1) * tmp_minifrag) % 256;
            if (i < k)
              buf[14 + 40 + 3]++;
            buflen = 14 + 40 + j;
            hdr.pkt_len = buflen;
            if ((method & 1024) == 1024) {
              buf[14 + 7] = evade_hop;
              memset(buf + 14 + 40 + 8, 'X', j - 8);
              memcpy(hdr.pkt, buf, buflen); // cant overflow thankfully
              thc_send_pkt(interface, (unsigned char *)&hdr, &buflen);
              buf[14 + 7] = tmp_hop;
            }
            memcpy(buf + 14 + 40 + 8, payload + 40 + ((i - 1) * tmp_minifrag), j - 8);
            memcpy(hdr.pkt, buf, buflen); // cant overflow thankfully
            thc_send_pkt(interface, (unsigned char *)&hdr, &buflen);
          }
        } else {
          dstmac = thc_ipv62notation(payload + 24);
          fprintf(stderr, "Error: could not get an Ethernet address to destination %s, dropping packet :-(\n", dstmac);
          drop = 1;
        }
        free(dstmac);
      }
      
      // fake fragmentation data
      if ((method & 1024) == 1024 && method > 1024 && drop == 0) {
        i = 0;
        j = 0;
        if (payload[6] == IP_PROTOCOL_FRAG) {
          while((40 + i*8) < len && payload[40 + i*8] == IP_PROTOCOL_FRAG)
            i++;
          j = 40 + i*8;
          if (j + 11 >= len)
            j = 0;
        }

        if (j) {
          // j points to the last fragment hdr start
          if ((dstmac = thc_get_mac(interface, NULL, payload + 24)) != NULL) {
            memcpy(buf, dstmac, 6); // create 2nd packet
            memcpy(buf + 6, ether, 8);
            memcpy(buf + 14, payload, len);
            buf[14 + 7] = evade_hop;
            for (i = 14 + j + 8 + 2; i < len + 14; i++) // we keep the first two bytes of the original packet
              buf[i] = 'X'; // random in the future
            // checksum correction for udp/tcp/icmpv6?
            buflen = len + 14;
            hdr.pkt_len = buflen;
            thc_send_pkt(interface, (unsigned char *)&hdr, &buflen); // send packet
          } else {
            dstmac = thc_ipv62notation(payload + 24);
            fprintf(stderr, "Error: could not get an Ethernet address to destination %s, dropping packet :-(\n", dstmac);
            drop = 1;
          }
          free(dstmac);
        }
      }
      
      // foo
      if ((method & 65536) == 65536) {
        drop = 1;
        
        printf("not done yet 65536\n");
      }
      
    } // END OF EVASION OPTIONS
    
    if (len > mtu && drop != 1) {
      if (buf[6] == IP_PROTOCOL_FRAG) {
        if ((dstmac = thc_get_mac(interface, NULL, payload + 24)) != NULL) {
          i = mtu - 40;
          payload[4] = i / 256;
          payload[5] = i % 256;
          if ((payload[40 + 3] & 1) == 1) // was the more-fragments bit set?
          j = 1;
          else { // no, so we have to set it
            j = 0;
            payload[40 + 3] += 1;
          }

          memcpy(buf, dstmac, 6); // create 2nd packet
          memcpy(buf + 6, ether, 8);
          memcpy(buf + 14, payload, 48);
          memcpy(buf + 14 + 48, payload + mtu, len - mtu);
          i = 8 + len - mtu;
          buf[14 + 4] = i / 256; // set ipv6 data len
          buf[14 + 5] = i % 256;
          k = buf[14 + 40 + 2] * 256 + buf[14 + 40 + 3] - 1; // original offset
          k += mtu - 40 - 8 + j; // add new offset (plus keep original more-fragment bit status
          buf[14 + 40 + 2] = k / 256; // set new frag offset
          buf[14 + 40 + 3] = k % 256;
          buflen = 14 + 40 + 8 + len - mtu;
          hdr.pkt_len = buflen;
          thc_send_pkt(interface, (unsigned char *)&hdr, &buflen); // send packet

          len = mtu; // send only up to len
        } else {
          dstmac = thc_ipv62notation(payload + 24);
          fprintf(stderr, "Error: could not get an Ethernet address to destination %s, dropping packet :-(\n", dstmac);
          drop = 1;
        }
        free(dstmac);
      } else { 
        drop = 1;
        fprintf(stderr, "BUG :: packet is larger than MTU but has no atomic fragment header - WTF? dropped!\n");
      }
    }

    // Netfilter supported verdicts:
    // - NF_DROP, drop the packet; don't continue traversal;
    // - NF_ACCEPT, continue traversal as normal;
    // - NF_STOLEN, I've taken over the packet; don't continue traversal;
    // - NF_QUEUE, queue the packet (usually for userspace handling);
    // - NF_REPEAT, call this hook again.
    // - NF_STOP, stop the packet (???)
    if (drop == 0)
      nfq_set_verdict(hq, id, NF_ACCEPT, len, payload);
    else
      nfq_set_verdict(hq, id, NF_DROP, 0, NULL);

    // Send a null message to put a break
    if (verbose)
      log_message(LOG_DEBUG, NULL);
  } else {
    log_message(LOG_WARNING, "Unable to read packet header");
    return 1;
  }

  return 0;
}

int netfilter_queue_startup(struct nfq_handle **h, struct nfq_q_handle **hq) {
  // Try to open netfilter queue handle
  if ((*h = nfq_open()) == NULL) {
    *h = 0;
    log_message(LOG_ERROR, "Error while opening netfilter queue");
    return EXITCODE_NFQ_OPEN_FAILED;
  }
  log_message(LOG_DEBUG, "Netfilter queue opened successfully");
  if (nfq_unbind_pf(*h, AF_INET6) != 0) {
    log_message(LOG_WARNING, "Failed to unbind AF_INET6 from netfilter queue, not a critical error");
  }
  // Bind the obtained nf queue handle to AF_INET6 protocol
  if (nfq_bind_pf(*h, AF_INET6) != 0) {
    log_message(LOG_ERROR, "Error while binding AF_INET6 protocol to handle");
    return EXITCODE_NFQ_BIND_FAILED;
  }
  log_message(LOG_DEBUG, "Netfilter queue will read only IPv6 packets");
  // Hook a queue
  if ((*hq = nfq_create_queue(*h, config.queue_number, config.queue_callback, NULL)) == NULL) {
    // Reset hq
    *hq = 0;
    log_message(LOG_ERROR, "Error while attaching to netfilter queue");
    return EXITCODE_NFQ_CREATEQUEUE_FAILED;
  }
  log_message(LOG_DEBUG, "Netfilter queue attached successfully");
  // Set copy mode for patckes
  if (nfq_set_mode(*hq, NFQNL_COPY_PACKET, 0xffff) != 0) {
    log_message(LOG_ERROR, "Error while setting copy packet mode");
    return EXITCODE_NFQ_SETMODE_FAILED;
  }
  log_message(LOG_DEBUG, "Netfilter copy packet mode set successfully");
  // All goes well
  return EXITCODE_OK;
}

int netfilter_queue_loop(struct nfq_handle **h, struct nfq_q_handle **hq) {
  int buffer_size = sizeof(char) * config.buffer_size;
  char *buffer = (char *) malloc(buffer_size);
  int poll_events;
  int recv_length;

  // Check if buffer was allocated
  if (buffer == NULL) {
    log_message(LOG_ERROR, "Error while allocating buffer for %d bytes for netfilter queue messages", sizeof(char) * config.buffer_size);
    return EXITCODE_NO_MEMORY;
  }
  // Set memory to zero
  memset(buffer, 0, buffer_size);
  // Set exit from main loop switch
  exit_from_loop = 0;
  // Initialize poll struct
  struct pollfd *fds = malloc(sizeof(struct pollfd));
  // Get netqueue netlink socket fd
  int fd = nfq_fd(*h);
  // Loop packets received by the queue
  do {
    memset(fds, 0, sizeof(struct pollfd));
    fds->fd = fd;
    fds->events = POLLIN | POLLRDHUP;
    // Use poll to check if there is stuff to read from netfilter socket
    if ((poll_events = poll(fds, 1, 50)) < 0) {
      // Verifica se l'errore ? di tipo 4 e se ? stata richiesta l'uscita
      // dal loop perch? in quel caso non va stampato nessun errore
      if (errno == 4 && exit_from_loop == 1) {
        // do nothing
      } else {
        // Advise the user
        log_message(LOG_ERROR, "Poll error");
        // Set exit from loop switch
        exit_from_loop = 1;
      }
    } else if (poll_events == 1) {
      // Check if socket shutdown for any reason
      if (fds->revents & POLLHUP) {
        // Advise the user
        log_message(LOG_ERROR, "Netfilter netlink socket closed unexpectedly");
        // Set exit from loop switch
        exit_from_loop = 1;
      }
      // Check if socket got an error (teorycally this stuff should be managed
      // by netfilter netlink subsystem, but few lines of code doesn't kill
      // anyone)
      else if (fds->revents & POLLERR) {
        // Advise the user
        log_message(LOG_ERROR, "Netfilter netlink socket error");
        // Set exit from loop switch
        exit_from_loop = 1;
      } else {
        // Read the stuff
        recv_length = recv(fds->fd, buffer, buffer_size, 0);

        // Pass the packet to netfilter queue banckend
        nfq_handle_packet(*h, buffer, recv_length);
      }
    }
  }
  while (exit_from_loop == 0);
  free(buffer);
  free(fds);
  return EXITCODE_OK;
}

int netfilter_queue_shutdown(struct nfq_handle **h, struct nfq_q_handle **hq) {
  // Check if queue was attached
  if (*hq != 0) {
    // Try to destroy the queue if it was attached
    if (nfq_destroy_queue(*hq) != 0) {
      log_message(LOG_ERROR, "Error while detaching from netfilter queue");
      return EXITCODE_NFQ_DESTROYQUEUE_FAILED;
    }
    log_message(LOG_DEBUG, "Netfilter queue detached successfully");
  }
  // Check if queue was opened
  if (*h != 0) {
    // Try to close the queue if it was opened
    if (nfq_close(*h) != 0) {
      log_message(LOG_ERROR, "Error while closing netfilter queue");
      return EXITCODE_NFQ_CLOSE_FAILED;
    }
    log_message(LOG_DEBUG, "Netfilter queue closed successfully");
  }
  // All goes well
  return EXITCODE_OK;
}

void signal_manager(int signal) {
  // Verifica il tipo di segnale passato
  switch (signal) {
  case SIGINT:
  case SIGQUIT:
  case SIGTERM:
    // Log the signal
    log_message(LOG_NOTICE, "User interrupt!");
    // Attiva lo switch per l'uscita dal sotware
    exit_from_loop = 1;
    break;
  }
}

int main(int argc, char **argv) {
  int i, exitcode;
  struct nfq_handle *h = 0;
  struct nfq_q_handle *hq = 0;
  char *ptr;

   while ((i = getopt(argc, argv, "hdve:f:t:")) >= 0) {
     switch (i) {
       case 'h':
         help(argv[0]);
         break;
       case 'f':
         minifrag = atoi(optarg);
         if (minifrag % 8 != 0 || minifrag < 8) {
           minifrag = (((minifrag / 8) + 1) * 8);
           fprintf(stderr, "Warning: mini fragment size must be a multiple of 8, setting to %d\n", minifrag);
         }
         break;
       case 'e':
         evade_hop = atoi(optarg);
         break;
       case 't':
         target_hop = atoi(optarg);
         break;
       case 'd':
         debug = 1;
         break;
       case 'v':
         verbose = 1;
         break;
     }
  }

  if (argc - optind != 2)
      help(argv[0]);
  
  if (!evade_hop && target_hop)
    evade_hop = target_hop - 1;
  
  interface = argv[optind];
  method = atoi(argv[optind + 1]);
  printf("Interface: %s\n", interface);
  printf("Evasion Mode: %u\n", method);
  if ((mtu = thc_get_mtu(interface)) < 1280 || (ptr = (char*)thc_get_own_mac(interface)) == NULL) {
    fprintf(stderr, "Error: invalid interface %s\n", interface);
    exit(-1);
  }
  if (method == 0)
    fprintf(stderr, "Warning: mode 0 does not perform any kind of evasion.\n");
  if (method > 2048 + 1024 + 512 + 256 + 128 + 64 + 32 + 31) {
    fprintf(stderr, "Error: modes > 2047 are not defined yet.\n");
    exit(-1);
  }
  if ((method & 1792) > 0 && !evade_hop) {
    fprintf(stderr, "Error: methods 256, 512 and 1024 require to specify the evade hop count to the IDS with the -e option.\n");
    exit(-1);
  }
  memcpy(ether, ptr, 6);
  ether[6] = 0x86;
  ether[7] = 0xdd;

  config.log_level = LOG_DEBUG;
  config.buffer_size = 8192;
  config.queue_number = 0;
  config.queue_callback = &netfilter_queue_callback;

  // Register signals
  signal(SIGINT, signal_manager);
  signal(SIGQUIT, signal_manager);
  signal(SIGTERM, signal_manager);

  // Startup netfilter queue
  if ((exitcode = netfilter_queue_startup(&h, &hq)) == EXITCODE_OK) {
    // If exit code is ok, start loop
    if ((exitcode = netfilter_queue_loop(&h, &hq)) == EXITCODE_OK) {
      // All done!
    }
  }
  // Try to close the engine in every case
  if ((exitcode = netfilter_queue_shutdown(&h, &hq)) == EXITCODE_OK) {
    // Advise that all gone well
    log_message(LOG_DEBUG, "All gone well!");
  }
  // Return exit code (EXITCODE_OK means all ok otherwise there was errors)
  return exitcode;
}

