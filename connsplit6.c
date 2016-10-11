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
int exit_from_loop = 0, verbose = 0, server = 0;
char *interface = NULL, ether[8];

void help(char *prg) {
  printf("splitconnect6 %s (c) 2016 by %s %s\n\n", VERSION, AUTHOR, RESOURCE);
  printf("Syntax: [-vd] %s INTERFACE client|server\n\n", prg);
  printf("Options:\n");
  printf("  -v   verbose mode\n");
  printf("  -d   debug mode\n");
  printf("\nManipulates all incoming (client) or outgoing (server) TCP connections that are\nfrom (server) or to (client) port %d, and sets a new destinatin (server) or\nsource (client) address.\n", THC_SPLITCONNECT_PORT);
  printf("The purpose of this is a proof of concept to make connect analysis difficult.\n");
  printf("It is recommended to use the splitconnect6.sh script to control this tool.\n");
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

    memcpy(payload, packet, len);

    // Manipulate the packet
    if (len >= 60) {
//printf("Len OK\n");
      if (payload[6] == NXT_TCP) {
//printf("TCP OK\n");
        int port = THC_SPLITCONNECT_PORT, pport;
        int modified = 0, checksum;
        unsigned char *src = payload + 8, *dst = payload + 24;
//printf("server %d frombyte %02x tobyte %02x\n", server, payload[39], payload[23]);
        if (server == 1 && payload[39] == THC_SPLITCONNECT_FROM_BYTE) {
          pport = (unsigned int)(((unsigned int) (payload[42] << 8)) + ((unsigned int) payload[43]));
//printf("port %d == %d\n", THC_SPLITCONNECT_PORT, pport);
          if (pport == THC_SPLITCONNECT_PORT) {
            payload[39] = THC_SPLITCONNECT_TO_BYTE;
            modified = 1;
          }
        }
        if (server == 0 && payload[39] == THC_SPLITCONNECT_TO_BYTE) {
          pport = (unsigned int)(((unsigned int) (payload[40] << 8)) + ((unsigned int) payload[41]));
//printf("port %d == %d\n", THC_SPLITCONNECT_PORT, pport);
          if (pport == THC_SPLITCONNECT_PORT) {
            payload[39] = THC_SPLITCONNECT_FROM_BYTE;
            modified = 1;
          }
        }
        if (modified) { // update TCP checksum
//printf("CHANGED\n");
          payload[56] = 0;
          payload[57] = 0;
          checksum = checksum_pseudo_header(src, dst, NXT_TCP, payload + 40, len - 40);
          payload[56] = checksum / 256;
          payload[57] = checksum % 256;
        }
      }
    }

    // Netfilter supported verdicts:
    // - NF_DROP, drop the packet; don't continue traversal;
    // - NF_ACCEPT, continue traversal as normal;
    // - NF_STOLEN, I've taken over the packet; don't continue traversal;
    // - NF_QUEUE, queue the packet (usually for userspace handling);
    // - NF_REPEAT, call this hook again.
    // - NF_STOP, stop the packet (???)
    nfq_set_verdict(hq, id, NF_ACCEPT, len, payload);

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
  int i, exitcode, mtu;
  struct nfq_handle *h = 0;
  struct nfq_q_handle *hq = 0;
  char *ptr;

   while ((i = getopt(argc, argv, "hdv")) >= 0) {
     switch (i) {
       case 'h':
         help(argv[0]);
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

  if (argv[optind + 1][0] == 'S' || argv[optind + 1][0] == 's')
    server = 1;
  else
  if (argv[optind + 1][0] == 'C' || argv[optind + 1][0] == 'c')
    server = 0;
  else {
    fprintf(stderr, "Error: you must supply either the keyword \"client\" or \"server\".\n");
    exit(-1);
  }
  
  interface = argv[optind];
  printf("Interface: %s\n", interface);
  printf("Mode: %u\n", server);
  if ((mtu = thc_get_mtu(interface)) < 1280 || (ptr = (char*)thc_get_own_mac(interface)) == NULL) {
    fprintf(stderr, "Error: invalid interface %s\n", interface);
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

