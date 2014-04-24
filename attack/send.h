#ifndef __SEND_H__
#define __SEND_H__

#include <netinet/in.h>		// struct in_addr

#define SYN 1
#define FIN 2
#define UDP 4
#define UDP_PAYLOAD 1000

void packet_send(struct in_addr ip, uint16_t port, uint8_t type);

#endif
