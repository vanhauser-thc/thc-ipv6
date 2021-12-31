#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef _HAVE_SSL
int main() {
  fprintf(stderr,
          "Error: thc-ipv6 was compiled without openssl support, covert_send6d "
          "disabled.\n");
  return -1;
}
#else
  #if (_TAKE2 > 0)
int main() {
  fprintf(stderr, "Error: tool does not work on big endian\n");
  return -1;
}
  #endif

  #include <sys/types.h>
  #include <sys/time.h>
  #include <sys/resource.h>
  #include <sys/wait.h>
  #include <time.h>
  #include <pcap.h>
  #include <openssl/blowfish.h>
  #include <openssl/sha.h>
  #include "thc-ipv6.h"

FILE * f;
BF_KEY bfkey;
int    rawmode = 0, seq = 1, id = 0, num = 0;
char   hash[20] = "", *key = NULL, vec[8] = {0, 0, 0, 0, 0, 0, 0, 0};

void help(char *prg) {
  printf("%s %s (c) 2022 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf("Syntax: %s [-k key] interface file\n\n", prg);
  printf("Options:\n");
  printf("  -k key     decrypt the content with Blowfish-160\n");
  printf("\n");
  printf("Writes covertly received content to FILE.\n");
  exit(-1);
}

void check_packets(u_char *foo, const struct pcap_pkthdr *header,
                   const unsigned char *data) {
  int len = header->caplen, rlen, bytes = 0, hlen, end = 0, pos, dlen = 0,
      done = 0;
  unsigned char *ptr = (unsigned char *)data, rbuf[6000], wbuf[6000];

  if (!rawmode) {
    if (do_hdr_size) {
      ptr += do_hdr_size;
      len -= do_hdr_size;
      if ((ptr[0] & 240) != 0x60) return;
    } else {
      ptr += 14;
      len -= 14;
    }
  }

  if (len < 58)  // too short
    return;
  if (ptr[6] != NXT_DST) return;
  if (ptr[42] != 0x10 || ptr[43] != 4 || ptr[48] != 0x11 || ptr[49] != 4 ||
      ptr[54] != 0x12)
    return;

  if (memcmp(ptr + 50, (char *)&seq, 4) != 0) return;

  if (seq == 1)
    memcpy((char *)&id, ptr + 44, 4);
  else if (memcmp(ptr + 44, (char *)&id, 4) != 0)
    return;

  dlen = 40 + (ptr[41] + 1) * 8;
  rlen = len - 54;
  pos = 54;
  while (rlen > 0 && end == 0 && dlen > pos && done == 0) {
    if (ptr[pos] == 0)
      done = 1;
    else if (ptr[pos] < 0x12)
      return;
    else if (ptr[pos] > 0x1f)
      return;
    else if (ptr[pos] == 0x1f)
      end = 1;
    else {
      if ((hlen = ptr[pos + 1]) >= rlen) return;
      if (bytes + hlen >= sizeof(rbuf)) return;
      memcpy(rbuf + bytes, ptr + pos + 2, hlen);
      rlen = rlen - (hlen + 2);
      pos = pos + hlen + 2;
      bytes = bytes + hlen;
    }
  }

  if (bytes > 0) {
    if (key != NULL) {
      BF_cfb64_encrypt((unsigned char *)rbuf, (unsigned char *)wbuf, bytes,
                       &bfkey, (unsigned char *)vec, &num, BF_DECRYPT);
      memcpy(rbuf, wbuf, bytes);
    }
    fwrite(rbuf, 1, bytes, f);
  }

  printf("Received packet seq# %d\n", seq);
  seq++;
  if (end) {
    printf("All received.\n");
    fclose(f);
    exit(0);
  }
}

int main(int argc, char *argv[]) {
  char *  interface;
  pcap_t *p;
  int     i;

  if (argc < 3 || strncmp(argv[1], "-h", 2) == 0) help(argv[0]);

  while ((i = getopt(argc, argv, "rk:")) >= 0) {
    switch (i) {
      case 'r':
        rawmode = 1;
        thc_ipv6_rawmode(1);
        break;
      case 'k':
        key = optarg;
        break;
      default:
        fprintf(stderr, "Unknown option\n");
        exit(-1);
    }
  }

  interface = argv[optind];
  if ((f = fopen(argv[optind + 1], "w")) == NULL) {
    fprintf(stderr, "Error: file %s cout not be created\n", argv[optind + 1]);
    exit(-1);
  }

  if (key != NULL) {
    memset(&bfkey, 0, sizeof(bfkey));
    SHA1((unsigned char *)key, strlen(key), (unsigned char *)hash);
    BF_set_key(&bfkey, sizeof(hash), (unsigned char *)hash);
    memset(vec, 0, sizeof(vec));
    num = 0;
  }

  if ((p = thc_pcap_init(interface, "ip6")) == NULL) {
    fprintf(stderr, "Error: could not capture on interface %s\n", interface);
    exit(-1);
  }

  while (1) {
    thc_pcap_check(p, (char *)check_packets, NULL);
    usleep(50);
  }

  return 0;
}

#endif
