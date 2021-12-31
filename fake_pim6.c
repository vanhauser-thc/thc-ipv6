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

void help(char *prg) {
  printf("%s %s (c) 2022 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf("Syntax:\n");
  printf(
      "  %s [-l|-f] [-t ttl] [-s src6] [-d dst6] interface hello "
      "[dr_priority]\n",
      prg);
  printf(
      "  %s [-l|-f] [-t ttl] [-s src6] [-d dst6] interface bootstrap bsr6 "
      "[bsr_prio [rp6]]\n",
      prg);
  printf(
      "  %s [-l|-f] [-t ttl] [-s src6] [-d dst6] interface assert multicast6 "
      "[metric [sender6]]\n",
      prg);
  printf(
      "  %s [-l|-f] [-t ttl] [-s src6] [-d dst6] interface join|prune "
      "neighbor6 multicast6 target6\n",
      prg);
  printf("\nOptions:\n");
  printf("  -l       loop packet every 5 seconds\n");
  printf(
      "  -f       flood packet (with random values where useful, e.g src)\n");
  printf("  -t ttl   specify a non-standard ttl\n");
  printf("  -s src6  specify the source IPv6 address\n");
  printf("  -d dst6  specify a non-standard destination IPv6 address\n");
  printf(
      "\nThe hello command takes optionally the DR priority (default: 0).\n");
  printf(
      "The join and prune commands need the multicast group to modify, the "
      "target\naddress that joins or leavs and the neighbor PIM router\n");
  printf(
      "The bootstrap command needs the bootstraprouter address and optional "
      "its\npriority and the rendevouz-point.\n");
  printf(
      "The assert command needs the concerning multicast address and optional "
      "its\nmetric and multicast sender.\n");
  exit(-1);
}

int main(int argc, char *argv[]) {
  unsigned char *pkt1 = NULL, buf[128];
  unsigned char *dst6 = NULL, *tmp6 = NULL, *src6 = NULL, *gsrc6 = NULL,
                *multicast6, *target6, *neighbor6;
  int           pkt1_len = 0, i = 0, j, rand_int, offset = 14;
  char *        interface;
  int           ttl, tmp_ttl = -1, mode = -1, len = 0, loop = 0, flood = 0;
  thc_ipv6_hdr *hdr;

  if (argc < 3 || strncmp(argv[1], "-h", 2) == 0) help(argv[0]);

  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  while ((i = getopt(argc, argv, "t:s:d:lf")) >= 0) {
    switch (i) {
      case 'f':
        flood = 1;
        break;
      case 'l':
        loop = 1;
        break;
      case 't':
        tmp_ttl = atoi(optarg);
        break;
      case 's':
        src6 = thc_resolve6(optarg);
        break;
      case 'd':
        dst6 = thc_resolve6(optarg);
        break;
      default:
        fprintf(stderr, "Error: invalid option %c\n", i);
        exit(-1);
    }
  }

  interface = argv[optind];
  if (strncasecmp(argv[optind + 1], "hello", 3) == 0) mode = 0;
  if (strncasecmp(argv[optind + 1], "join", 3) == 0) mode = 3;
  if (strncasecmp(argv[optind + 1], "prune", 3) == 0) mode = 256 + 3;
  if (strncasecmp(argv[optind + 1], "bootstrap", 4) == 0) mode = 4;
  if (strncasecmp(argv[optind + 1], "assert", 3) == 0) mode = 5;
  if (strcasecmp(argv[optind + 1], "register") == 0) mode = 1;
  if (strncasecmp(argv[optind + 1], "register", 9) == 0 &&
      strlen(argv[optind + 1]) > 9)
    mode = 2;  // register-stop
  if (mode == -1) {
    fprintf(stderr,
            "Error: no mode defined, specify hello, bootstrap, assert, join or "
            "prune\n");
    exit(-1);
  }
  if (flood && loop) loop = 0;
  if (do_hdr_size) offset = do_hdr_size;

  if ((mode == 4) && argc - optind < 3) {
    fprintf(stderr,
            "Error: bootstrap mode needs to specify at least a BSR address\n");
    exit(-1);
  }
  if ((mode == 5) && argc - optind < 3) {
    fprintf(
        stderr,
        "Error: assert mode needs to specify at least a multicast6 address\n");
    exit(-1);
  }
  if (mode % 16 == 3) {
    if (argc - optind != 5) {
      fprintf(stderr,
              "Error: join/prune mode need a multicast and target address\n");
      exit(-1);
    }
    neighbor6 = thc_resolve6(argv[optind + 2]);
    multicast6 = thc_resolve6(argv[optind + 3]);
    target6 = thc_resolve6(argv[optind + 4]);
    if (multicast6 == NULL || target6 == NULL || neighbor6 == NULL) {
      fprintf(stderr, "Error: unable to resolve addresses\n");
      exit(-1);
    }
  }

  if (thc_get_own_ipv6(interface, NULL, PREFER_LINK) == NULL) {
    fprintf(stderr, "Error: invalid interface %s\n", interface);
    exit(-1);
  }

  if (mode != 1 && mode != 2 && mode < 6) {
    if (tmp_ttl == -1)
      ttl = 1;
    else
      ttl = tmp_ttl;
    if (dst6 == NULL) dst6 = thc_resolve6("ff02::d");
    if ((pkt1 = thc_create_ipv6_extended(interface, PREFER_LINK, &pkt1_len,
                                         src6, dst6, ttl, 0, 0, 0, 0)) == NULL)
      return -1;
  } else {
    // need dst6
    printf("TODO\n");
    if (tmp_ttl == -1)
      ttl = 255;
    else
      ttl = tmp_ttl;
    if ((pkt1 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt1_len,
                                         src6, dst6, ttl, 0, 0, 0, 0)) == NULL)
      return -1;
  }

  memset(buf, 0, sizeof(buf));
  srandom(time(NULL));
  rand_int = random();
  gsrc6 = thc_get_own_ipv6(interface, dst6, PREFER_GLOBAL);

  // here we set buf and len
  switch (mode % 16) {
    case 0:        // hello
      buf[1] = 1;  // opt 1
      buf[3] = 2;  // len 2
      buf[5] = 255;
      buf[7] = 19;  // opt 19
      buf[9] = 4;   // len 4
      if (argc - optind >= 3) {
        i = atoi(argv[optind + 2]);
        buf[10] = i / 256 * 256 * 256;
        buf[11] = (i / 65536) % 256;
        buf[12] = (i % 65536) / 256;
        buf[13] = i % 256;
      }
      buf[15] = 20;  // opt 20
      buf[17] = 4;   // len 4
      memcpy(buf + 18, (char *)&rand_int + _TAKE4, 4);
      buf[23] = 2;  // opt 2
      buf[25] = 4;  // len 4
      memset(buf + 26, 0x01, 4);
      len = 30;
      if (gsrc6 != NULL) {
        buf[31] = 24;  // opt 24
        buf[33] = 18;  // len 18
        buf[34] = 2;
        memcpy(buf + 36, gsrc6, 16);
        len += 22;
      }
      break;
    case 4:  // bootstrap
      // argv[optind + 2] == bsr, 3 prio, 4 rp
      buf[0] = 5;
      buf[1] = 0x7d;
      if (argc - optind >= 4)
        i = atoi(argv[optind + 3]);
      else
        i = 1;
      buf[3] = i;
      buf[4] = 2;
      if ((tmp6 = thc_resolve6(argv[optind + 2])) == NULL) {  // must exist
        fprintf(stderr, "Error: could not resolve bsr6: %s\n",
                argv[optind + 2]);
        exit(-1);
      }
      memcpy(buf + 6, tmp6, 16);
      buf[22] = 2;
      buf[25] = 8;  // mask
      tmp6 = thc_resolve6("ff00::");
      memcpy(buf + 26, tmp6, 16);
      if (argc - optind >= 5) {
        buf[42] = 1;
        buf[43] = 1;
        buf[46] = 2;
        if ((tmp6 = thc_resolve6(argv[optind + 4])) == NULL) {  // must exist
          fprintf(stderr, "Error: could not resolve rp6: %s\n",
                  argv[optind + 4]);
          exit(-1);
        }
        memcpy(buf + 48, tmp6, 16);
        buf[65] = 0x96;  // holdtime
        buf[66] = 7;     // prio
        len = 68;
      } else {
        buf[42] = 0;
        buf[43] = 0;
        len = 46;
      }
      break;
    case 5:                                                   // assert
      if ((tmp6 = thc_resolve6(argv[optind + 2])) == NULL) {  // must exist
        fprintf(stderr, "Error: could not resolve multicast6: %s\n",
                argv[optind + 2]);
        exit(-1);
      }
      buf[0] = 2;
      buf[3] = 128;  // /128 mask
      memcpy(buf + 4, tmp6, 16);
      buf[20] = 2;
      if (argc - optind >= 5) {
        if ((tmp6 = thc_resolve6(argv[optind + 4])) == NULL) {  // must exist
          fprintf(stderr, "Error: could not resolve sender6: %s\n",
                  argv[optind + 3]);
          exit(-1);
        }
        memcpy(buf + 16 + 6, tmp6, 16);
      } else
        buf[32 + 6] = 0x80;
      if (argc - optind >= 4) {
        i = atoi(argv[optind + 3]) % 65536;
        buf[34 + 6] = i >> 8;
        buf[35 + 6] = i % 256;
        buf[38 + 6] = i >> 8;
        buf[39 + 6] = i % 256;
      } else {
        buf[34 + 6] = 1;  // metric 256
        buf[38 + 6] = 1;  // metric 256
      }
      len = 40 + 6;
      break;
    case 1:
    case 2:
    case 8:
      printf("TODO\n");
      //
      break;
    default:  // join/prune
      buf[0] = 2;
      memcpy(buf + 2, neighbor6, 16);
      buf[19] = 1;
      buf[21] = 255;
      buf[22] = 2;
      buf[25] = 128;
      memcpy(buf + 26, multicast6, 16);
      if (mode < 16)
        buf[43] = 1;
      else
        buf[45] = 1;
      buf[46] = 2;
      buf[48] = 7;
      buf[49] = 128;
      memcpy(buf + 50, target6, 16);
      len = 66;
  }

  if (thc_add_pim(pkt1, &pkt1_len, mode, buf, len) < 0) return -1;
  if (thc_generate_pkt(interface, NULL, NULL, pkt1, &pkt1_len) < 0) {
    fprintf(stderr, "Error: Can not generate packet, exiting ...\n");
    exit(-1);
  }

  if (loop || flood) {
    printf("%s PIM ", loop == 1 ? "Looping" : "Flooding");
    switch (mode) {
      case 0:
        printf("hello");
        break;
      case 1:
        printf("register");
        break;
      case 2:
        printf("register-end");
        break;
      case 3:
        printf("join");
        break;
      case 4:
        printf("bootstrap");
        break;
      case 5:
        printf("assert");
        break;
      case 259:
        printf("prune");
        break;
    }
    printf(" message (loop)\n");
  }
  i = 0;
  hdr = (thc_ipv6_hdr *)pkt1;
  do {
    if (flood) {
      i++;
      if (i % 1000 == 0) printf(".");
      memcpy(hdr->pkt + offset + 20, (char *)&i + _TAKE4, 4);  // src change
      switch (mode % 16) {
        case 0:
          memcpy(hdr->pkt + offset + 62, (char *)&i + _TAKE4, 4);
          memcpy(hdr->pkt + offset + 62 + 30, (char *)&i + _TAKE4, 4);
          break;
        case 4:
          memcpy(hdr->pkt + offset + 62, (char *)&i + _TAKE4, 4);
          break;
        case 5:
          memcpy(hdr->pkt + offset + 60, (char *)&i + _TAKE4, 4);
          break;
        default:
          fprintf(stderr, "Error: this mode does not support flooding yet\n");
          exit(-1);
      }
      hdr->pkt[offset + 56 - 14] = 0;
      hdr->pkt[offset + 57 - 14] = 0;
      j = checksum_pseudo_header(hdr->pkt + offset + 8, hdr->pkt + offset + 24,
                                 NXT_PIM, &hdr->pkt[offset + 40],
                                 hdr->pkt_len - offset - 40);
      hdr->pkt[offset + 56 - 14] = j / 256;
      hdr->pkt[offset + 57 - 14] = j % 256;
    }
    do {
      while (thc_send_pkt(interface, pkt1, &pkt1_len) < 0)
        usleep(5);
      if (loop) sleep(5);
    } while (loop == 1);
  } while (flood == 1);

  printf("Sent PIM ");
  switch (mode) {
    case 0:
      printf("hello");
      break;
    case 1:
      printf("register");
      break;
    case 2:
      printf("register-end");
      break;
    case 3:
      printf("join");
      break;
    case 4:
      printf("bootstrap");
      break;
    case 5:
      printf("assert");
      break;
    case 259:
      printf("prune");
      break;
  }
  printf(" message\n");

  return 0;
}
