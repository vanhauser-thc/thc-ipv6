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
#include <thc-ipv6.h>

#define HOST_SCAN_C_
#include "host_scan.h"
#undef   HOST_SCAN_C_

#define ETH_HDR_LEN	14      // Extensão do cabeçalho Ethernet
#define IP6_HDR_LEN	40      // Extensão do cabeçalho IPv6
#define BUF_SIZE	16      // Extensão do Buffer de Envio
#define PKT_FLAGS	0xdeadbeef      // Flags de envio do pacote [ID|SEQ]

extern int debug;               // variavel que indica se o debug esta ativo ou nao 
unsigned char buf[BUF_SIZE];    // Buffer de dados de envio 
unsigned char *alive[65536];    // tabela de hosts encontrados [Armazena Endereços IP]
unsigned char *aliveMac[65536]; // tabela de hosts encontrados [Armazena endereços MAC]
int alive_no = 0;               // contador do numero de hosts encontrados

// funcao de ajuda do programa

void help(char *prg) {
  printf("code by Fabricio Nogueira Buzeto and Carlos Botelho De Paula Filho\n\n");
  printf("Syntax: %s [-r] interface [unicast-or-multicast-address [remote-router]]\n", prg);
  printf("Shows alive addresses in the segment. If you specify a remote router, the\n");
  printf("packets are sent with a routing header prefixed by fragmentation\n");
//  printf("Use -r to use raw mode.\n");
  exit(-1);
}

/**  Funcao de captura de pacotes [eh passada como parametro para a pcap ]
u_char *foo --> ???
const struct pcap_pkthdr *header --> Cabecalho contendo informacoes sobre o pacote capturado
				fields:
					ts : uma "struct timeval" contendo o tempo onde o pacote foi capturado
					caplen : um "bpf_u_int32" contendo o numero de bytes da captura disponivel
					len : um "bpf_u_int32" contendo o numero total de bytes obtidos na captura [que pode ser superior ao numero de bytes disponiveis] 
const unsigned char *data --> campo de dados do pacote capturado [No caso o pacote ipv6]
*/
void check_packets(u_char * foo, const struct pcap_pkthdr *header, const unsigned char *data) {
  int i, ok = 1;
  unsigned char *ptr = (unsigned char *) data + 14;     // pulando para o campo de src addr

  // Funcao de debug, realiza o dump do pacote capturado na tela
  if (debug) {
    thc_dump_data(ptr, header->caplen - 14, "Received Packet");
  }
  // Verificacao caso o IP[Host] ja tenha sido dado como "alive" 
  i = 0;
  while (ok && i < alive_no) {
    if ((memcmp(alive[i], ptr + 8, 16) == 0)
        && (memcmp(aliveMac[i], ptr - 8, 6) == 0))
      ok = 0;
    i++;
  }

  // Se passou em todas as verificacoes, o endereco de origem eh armazenado em memoria
  if (ok && ((alive[alive_no] = malloc(16)) != NULL)
      && ((aliveMac[alive_no] = malloc(6)) != NULL)) {
    printf(".");
    memcpy(alive[alive_no], (ptr + 8), 16);
    memcpy(aliveMac[alive_no], (ptr - 8), 6);
    alive_no++;
  }
}

/**
  Função de auxílio para a impressão de endereços MAC
  	unsigned char *ptr --> Endereço MAC a ser impresso na saida padrão
 */
void printMAC(unsigned char *ptr) {
  printf("%02X-%02X-%02X-%02X-%02X-%02X", *(ptr), *(ptr + 1), *(ptr + 2), *(ptr + 3), *(ptr + 4), *(ptr + 5));
}

/**
  Função de auxílio para a impressão de endereços IPv6
  	unsigned char *ptr --> Endereço IPv6 a ser impresso na saida padrão
 */
void printIP6(unsigned char *ptr) {
  printf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
         *(ptr), *(ptr + 1), *(ptr + 2), *(ptr + 3), *(ptr + 4), *(ptr + 5), *(ptr + 6), *(ptr + 7),
         *(ptr + 8), *(ptr + 9), *(ptr + 10), *(ptr + 11), *(ptr + 12), *(ptr + 13), *(ptr + 14), *(ptr + 15));
}

/**
  Função que imprime os resultados do scan.
  Acessa as estrutiras alive[] e aliveMac[] afim de obter os endereços dos hosts encontrados na varredura
  bem como o contador alive_no, utilizado para manter a contagem do número de hosts encontrados. 
 */
void printAliveSystems() {
  int i;

  printf("Foram Encontrados %d Sistemas IPv6\n", alive_no);
  printf("+-----------------------------------------+-------------------+\n");
  printf("|      IP6                                |        MAC        |\n");
  printf("+-----------------------------------------+-------------------+\n");
  for (i = 0; i < alive_no; i++) {
    printf("| ");
    printIP6(alive[i]);
    printf(" | ");
    printMAC(aliveMac[i]);
    printf(" |\n");
  }
  printf("+-----------------------------------------+-------------------+\n");
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
  Função que realiza o envio de um pacote Echo Request, contendo uma falha no campo de opções, para na interface especificada para o endereço de multicast passado como parâmetro.
 */
int sendEchoRequestOptions(char *interface,     // Interface inde se sendrá o pacote
                           unsigned char *multicast6,   // Enedereço de Multicast IPv6 [destino]
                           unsigned char *src6, // Enedereço do host que send o pacote [IPv6]
                           unsigned char *router6,      // Roteador [NULL caso não necessite]
                           unsigned char **routers,      // Lista de Roteamento
                           unsigned char *buf,  // Buffer contendo os dados a serem senddos
                           unsigned char *mac) {        // Endereço do host q send o pacote [MAC]

  int pkt2_len = 0;             // Tamanho do pacote a ser senddo
  unsigned char *pkt2 = NULL;   // Pacote a ser montado e senddo
  thc_ipv6_hdr *hdr;            // Estrutura do header IPv6

  // cria o segundo pacote para o endereco de multicast
  if ((pkt2 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt2_len, src6, multicast6, 0, 0, 0, 0, 0)) == NULL)
    return -1;

  // caso tenha sido setado uma rota e adicionado um header de rota
  if (router6 != NULL)
    if (thc_add_hdr_route(pkt2, &pkt2_len, routers, 1) < 0)
      return -1;

  // adiciona um header invalido ???
  if (thc_add_hdr_misc(pkt2, &pkt2_len, NXT_INVALID, -1, (unsigned char *) &buf, BUF_SIZE) < 0)
    return -1;

  // adiciona um echo request
  if (thc_add_icmp6(pkt2, &pkt2_len, ICMP6_PINGREQUEST, 0, PKT_FLAGS, (unsigned char *) &buf, BUF_SIZE, 0) < 0)
    return -1;

  // encapsula o pacote
  thc_generate_pkt(interface, NULL, mac, pkt2, &pkt2_len);

  // se for para uma rota send como fragmento ??
  if (router6 != NULL) {
    hdr = (thc_ipv6_hdr *) pkt2;
    thc_send_as_fragment6(interface,
                          src6,
                          multicast6,
                          NXT_ROUTE,
                          hdr->pkt + IP6_HDR_LEN + ETH_HDR_LEN,
                          hdr->pkt_len - IP6_HDR_LEN - ETH_HDR_LEN, hdr->pkt_len > 1448 ? 1448 : (((hdr->pkt_len - IP6_HDR_LEN - ETH_HDR_LEN) / 16) + 1) * 8);
  } else                        // senao send o pacote normalmente
    thc_send_pkt(interface, pkt2, &pkt2_len);
}

int sendEchoRequestHopByHop(char *interface,    // Interface inde se sendrá o pacote
                            unsigned char *multicast6,  // Enedereço de Multicast IPv6 [destino]
                            unsigned char *src6,        // Enedereço do host que send o pacote [IPv6]
                            unsigned char *router6,     // Roteador [NULL caso não necessite]
                            unsigned char **routers,     // Lista de Roteamento
                            unsigned char *buf, // Buffer contendo os dados a serem senddos
                            unsigned char *mac) {       // Endereço do host q send o pacote [MAC] 

  int pkt3_len = 0;             // Tamanho do pacote a ser senddo
  unsigned char *pkt3 = NULL;   // Pacote a ser montado e senddo
  thc_ipv6_hdr *hdr;            // Estrutura do header IPv6;

  // cria o 3o pacote para o endereco de multicast 
  if ((pkt3 = thc_create_ipv6_extended(interface, PREFER_GLOBAL, &pkt3_len, src6, multicast6, 0, 0, 0, 0, 0)) == NULL)
    return -1;

  // caso tenha sido setado uma rota e adicionado um header de rota
  if (router6 != NULL)
    if (thc_add_hdr_route(pkt3, &pkt3_len, routers, 1) < 0)
      return -1;

  // adiciona um cabecalho hop by hop ???
  if (thc_add_hdr_hopbyhop(pkt3, &pkt3_len, (unsigned char *) &buf, BUF_SIZE) < 0)
    return -1;

  // adiciona um cabecalho echo request
  if (thc_add_icmp6(pkt3, &pkt3_len, ICMP6_PINGREQUEST, 0, PKT_FLAGS, (unsigned char *) &buf, BUF_SIZE, 0) < 0)
    return -1;

  // encapsula o pacote
  thc_generate_pkt(interface, NULL, mac, pkt3, &pkt3_len);

  // se for para uma rota send como fragmento ??
  if (router6 != NULL) {
    hdr = (thc_ipv6_hdr *) pkt3;
    thc_send_as_fragment6(interface,
                          src6,
                          multicast6,
                          NXT_ROUTE,
                          hdr->pkt + IP6_HDR_LEN + ETH_HDR_LEN,
                          hdr->pkt_len - IP6_HDR_LEN - ETH_HDR_LEN, hdr->pkt_len > 1448 ? 1448 : (((hdr->pkt_len - IP6_HDR_LEN - ETH_HDR_LEN) / 16) + 1) * 8);
  } else                        // senao send o pacote normalmente
    thc_send_pkt(interface, pkt3, &pkt3_len);
}

/**
  Função principal que realiza o host scan IPv6 na rede
 */
int hostScan(int rawmode,       // informa se o "raw mode" foi ativado ou nao
             char *interface,   // nome da interface de analise
             unsigned char *multicast6, // endereco do grupo multicast de destino
             unsigned char *router6,    // roteador da rota parametrizada
             unsigned char **routers) {
  unsigned char *src6 = NULL,   // endereco ip6 do host [que realiza o scan]
    *mac = NULL,                // endereco MAC do host [que realiza o scan]
    string[64] = "ip6 and dst ";        // Mascara de captura de pacotes [apenas 1pv6 e destino a ser marcado]
  time_t passed;                // timestamp do inicio do scan
  pcap_t *p;                    // contexto pcap de captura

  // obtendo seu proprio endereco ip6
  src6 = thc_get_own_ipv6(interface, multicast6, PREFER_GLOBAL);

  // se estiver operando em "raw mode" deve-se resolver seu proprio endereco MAC
  if (rawmode == 0 && (mac = thc_get_mac(interface, src6, multicast6)) == NULL) {
    fprintf(stderr, "ERROR: Can not resolve mac address for %s\n", thc_ipv62string(src6));
    exit(-1);
  }
  // setar o endereco do host para a filtragem de pacotes recebidos
  strcat(string, thc_string2notation(thc_ipv62string(src6)));

  // make the sending buffer unique
  memset(buf, 'A', sizeof(buf));        // Preenche o buffer com o caractere 'A'
  time((time_t *) & buf[2]);    // coloca da 3a posicao do buffer o tempo em segundos [padrao]
  buf[10] = getpid() % 256;     // coloca o valor do process id ..
  buf[11] = getpid() / 256;     // .. nas posicoes 11 e 12 do buffer
  memcpy(&buf[12], multicast6, 4);      // coloca o endereco de multicast na 13a posicao do buffer

  // inicializa a interface de captura de pacotes com o filtro criado
  if ((p = thc_pcap_init(interface, string)) == NULL) {
    fprintf(stderr, "Error: could not capture on interface %s with string %s\n", interface, string);
    exit(-1);
  }
  // Envio do 1o pacote : Echo Request Comum
  sendEchoRequest(interface, multicast6, src6, router6, routers, buf, mac, NULL);

  // Envio do 2o pacote : Echo Request Com falha de Opções 
  sendEchoRequestOptions(interface, multicast6, src6, router6, routers, buf, mac);

  // altera os dados do buffer ???
  buf[0] = NXT_INVALID;
  buf[1] = 1;

  // Envio do 3o pacote : Echo Request Com dados Hop by Hop
  sendEchoRequestHopByHop(interface, multicast6, src6, router6, routers, buf, mac);

  // ???
  while (thc_pcap_check(p, (char *) check_packets, NULL) > 0 && (alive_no == 0 || *multicast6 == 0xff));

  // Anota o tempo de inicio
  passed = time(NULL);
  // enquanto nao se passam 5 segundos
  while (passed + 5 >= time(NULL) && (alive_no == 0 || *multicast6 == 0xff))
    thc_pcap_check(p, (char *) check_packets, NULL);  // verifica os pacotes capturados

  // fecha a interface de captura
  thc_pcap_close(p);

  // informa o numero de hosts ativos encontrados
  //printf("Found %d systems alive\n", alive_no);
  printf("\n");
  printAliveSystems();
}

int main(int argc, char *argv[]) {
  unsigned char *router6 = NULL;        // roteador da rota parametrizada
  unsigned char *multicast6,    // endereco do grupo multicast de destino
   *routers[2];
  int rawmode = 0;              // informa se o "raw mode" foi ativado ou nao
  char *interface;              // nome da interface de analise


  // verifica se foi pedida as instrucoes de uso
  if (argc < 2 || strncmp(argv[1], "-h", 2) == 0)
    help(argv[0]);

  // verifica se foi selecionado para funcionar em "raw mode"
  if (strcmp(argv[1], "-r") == 0) {
    thc_ipv6_rawmode(1);
    rawmode = 1;
    argv++;
    argc--;
  }
  // nome da interface de captura
  interface = argv[1];

  // pode ser informado um grupo multicast para se limitar o escopo do scan
  if (argv[2] != NULL && argc > 2)
    multicast6 = thc_resolve6(argv[2]);
  else                          // caso nao tenha sido informado eh utilizado o endereco de multicast[broadcast] padrao
    multicast6 = thc_resolve6("ff02::1");

  // caso seja passado alguma rota , setar os roteadores 
  if (argv[3] != NULL && argc > 3) {
    router6 = thc_resolve6(argv[3]);
    routers[0] = multicast6;
    routers[1] = NULL;
    multicast6 = router6;       // switch destination and router
  }

  hostScan(rawmode, interface, multicast6, router6, routers);

  return 0;
}
