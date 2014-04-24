#ifndef __PARSER_H__
#define __PARSER_H__ 1

#include "captype.h"

#define dETHDR		node->data.ethdr
#define fETHDR		&node->flag.ethdr
#define dIPHDR		node->data.iphdr
#define fIPHDR		&node->flag.iphdr
#define dTCPHDR		node->data.hdr.tcp
#define fTCPHDR		&node->flag.hdr.tcp
#define dUDPHDR		node->data.hdr.udp
#define fUDPHDR		&node->flag.hdr.udp

#define isNUM(CHAR)	((CHAR) >= '0' && (CHAR) <= '9')
#define isUPPER(CHAR)	((CHAR) >= 'A' && (CHAR) <= 'F')
#define isLOWER(CHAR)	((CHAR) >= 'a' && (CHAR) <= 'f')

void parse(FILE *fp, struct linkedlist *node);

#endif
