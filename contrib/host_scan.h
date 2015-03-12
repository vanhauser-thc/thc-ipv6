#ifndef HOST_SCAN_H_
#define HOST_SCAN_H_

#if defined (HOST_SCAN_C)
#define HOST_SCAN_EXT
#else
#define HOST_SCAN_EXT extern
#endif

/**
  Função que realiza o envio de um pacote Echo Request para na interface especificada para o endereço de multicast
  passado como parâmetro.
 */
HOST_SCAN_EXT int sendEchoRequest(char *interface,      // Interface inde se sendrá o pacote
                                  unsigned char *multicast6,    // Enedereço de Multicast IPv6 [destino]
                                  unsigned char *src6,  // Enedereço do host que send o pacote [IPv6]
                                  unsigned char *router6,       // Roteador [NULL caso não necessite]
                                  unsigned char **routers,       // Lista de Roteamento
                                  unsigned char *buf,   // Buffer contendo os dados a serem senddos
                                  unsigned char *mac,   // Endereço do host de destino [MAC]
                                  unsigned char *macsrc);       // Endereço do host q send o pacote [MAC]

#undef HOST_SCAN_EXT
#endif
