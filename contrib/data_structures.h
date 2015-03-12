#ifndef DATA_STRUCTURES_H_
#define DATA_STRUCTURES_H_

typedef struct {
  char *interface;
  unsigned char *uniOrMultiCastAddr;
  //char *router;
  int rawMode;
} HArgs;

typedef struct {
  char *interface;
  unsigned char *ipAddr;
  int rawMode;
  unsigned char *ownIp;
  unsigned char *ownMac;
} RArgs;

typedef struct {
  char *interface;
  unsigned char *ipAddrVic1, *ipAddrVic2;
  unsigned char *macAddrVic1, *macAddrVic2;
  int twoVics;
  int rawMode;
  unsigned char *ownIp;
  unsigned char *ownMac;
} MArgs;

#endif /*DATA_STRUCTURES_H_ */
