#ifndef __FILTER_H__
#define __FILTER_H__ 1

#include "parser.h"
#include "captype.h"

void menu(struct linkedlist *node, const pid_t pid);
char* gettime();
void rawprint(const uint8_t * const packet, int packetlen);

#define DSTMAC(PKT)	*((PKT) +  0)
#define SRCMAC(PKT)	*((PKT) +  6)
#define ETHERTYPE(PKT)	*((PKT) + 12)
#define VERSION(PKT)	*((PKT) + 14)  // 4 bit
#define IPHLEN(PKT)	*((PKT) + 14)  // 4 bit
#define TOS(PKT)	*((PKT) + 15)
#define IPLEN(PKT)	*((PKT) + 16)
#define IPID(PKT)	*((PKT) + 18)
#define FRAGMENT(PKT)	*((PKT) + 20)  // 3 bit
#define IPOFF(PKT)	*((PKT) + 20)  // 13 bit 
#define TTL(PKT)	*((PKT) + 22)
#define PROTOCOL(PKT)	*((PKT) + 23)
#define IPCKSUM(PKT)	*((PKT) + 24)
#define SRCIP(PKT)	*((PKT) + 26)
#define DSTIP(PKT)	*((PKT) + 30)
#define SRCPORT(PKT)	*((PKT) + 34)
#define DSTPORT(PKT)	*((PKT) + 36)
#define SEQ(PKT)	*((PKT) + 38)
	#define UDPLEN(PKT)	*((PKT) + 38)
	#define UDPCKSUM(PKT)	*((PKT) + 40)
#define ACK(PKT)	*((PKT) + 42)
#define TCPOFF(PKT)	*((PKT) + 46)  // 4 bit
#define TCPRES(PKT)	*((PKT) + 46)  // 4 bit
#define TCPFLAG(PKT)	*((PKT) + 47)
#define WINDOW(PKT)	*((PKT) + 48)
#define TCPCKSUM(PKT)	*((PKT) + 50)
#define URGPTR(PKT)	*((PKT) + 52)

#endif
