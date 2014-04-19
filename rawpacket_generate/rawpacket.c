#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>

#include "rawpacket.h"

#define FREE_RET  do{ close(sockfd); return false; }while(0)

void rawprint(const uint8_t * const packet, int packetlen);

bool packet_send(uint8_t *packet)
{
	int sockfd, done = 0;
	int packetlen = 0, payloadlen = 0;

	char *payload;
	struct ip *iphdr;
	struct ifreq ifr;
	struct sockaddr_ll sll;


	/* PACKET */
	if( (sockfd = socket(PF_PACKET, SOCK_RAW, IPPROTO_RAW)) < 0 ) {
		perror("socket(): ");
		return false;
	}

	//random payload

	/* ETHER HEADER */
	if( ether_create((struct ether_header *)packet, sockfd) == false ) {
		printf("ether_create(): Failure\n");
		FREE_RET;
	}
	packetlen += sizeof(struct ether_header);  // 14 bytes


	/* IP HEADER */
	iphdr = (struct ip *)(packet + packetlen);
	if( iphdr_create(iphdr, flow->ip, flow->type, payloadlen) == false ) {
		printf("iphdr_create(): Failure\n");
		FREE_RET;
	}
	packetlen += sizeof(struct ip);  // 20 bytes


	if( flow->type == UDP ) {
		/* UDP HEADER */
		if( udphdr_create((struct udphdr *)(packet + packetlen), flow->port, payload, payloadlen, iphdr) == false ) {
			printf("udphdr_create(): Failure\n");
			FREE_RET;
		}
		packetlen += sizeof(struct udphdr);  // 8 bytes


	}else {
		/* TCP HEADER */
		if( tcphdr_create((struct tcphdr *)(packet + packetlen), flow->port, flow->type, payload, payloadlen, iphdr) == false ) {
			printf("tcphdr_create(): Failrue\n");
			FREE_RET;
		}
		packetlen += sizeof(struct tcphdr);  // 20 bytes
	}


	/* PAYLOAD */
	memcpy(packet + packetlen, payload, payloadlen);
	packetlen += payloadlen;


	/* SEND PACKET */
	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, "eth0", IFNAMSIZ-1);

	if( ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0 ) {
		perror("ioctl(): ");
		FREE_RET;
	}

	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifr.ifr_ifindex;

	if( bind(sockfd, (struct sockaddr *)&sll, sizeof(sll)) < 0 ) {
		perror("bind(): ");
		FREE_RET;
	}

	//rawprint(packet, packetlen);

	if( (done = write(sockfd, packet, packetlen)) != packetlen )
		printf("Miss %d bytes\n", packetlen - done);

	close(sockfd);
	free(packet);

	return true;
}

void rawprint(const uint8_t * const packet, int packetlen)
{
	printf("------- RAW -------\n");
	int i = 0;
	while( i < packetlen ) {
		printf("%02x ", *(packet+i));
		if( ++i%16 == 0 ) printf("\n");
	}
	if( i%16 != 0 ) printf("\n-------------------\n");
	else printf("-------------------\n");
}
