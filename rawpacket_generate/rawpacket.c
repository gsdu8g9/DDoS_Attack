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

bool packet_send(uint8_t *packet, TYPE type)
{
	int sockfd, done = 0;
	int packetlen = 0, payloadlen = 0;

	char *payload;
	struct ip *iphdr;
	struct sockaddr_in din;
	int one = 1;
	const int *val = &one;

	/* PACKET */
	if( (sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW)) < 0 ) {
		perror("socket(): ");
		return false;
	}

	// Address family
	din.sin_family      = AF_INET;
	din.sin_addr.s_addr = iphdr->ip_dst.s_addr;
	din.sin_port        = tcphdr->dest;

	if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
		perror("setsockopt() error");
		exit(-1);
	}

	//random payload

	/* IP HEADER */
	iphdr = (struct ip *)packet;
	packetlen += sizeof(struct ip);  // 20 bytes


	if( type == UDP ) {
		/* UDP HEADER */
		packetlen += sizeof(struct udphdr);  // 8 bytes

	}else {
		/* TCP HEADER */
		packetlen += sizeof(struct tcphdr);  // 20 bytes
	}

	/* PAYLOAD */
	memcpy(packet + packetlen, payload, payloadlen);
	packetlen += payloadlen;

	/* SEND PACKET */
	while( 1 ) {

		int x = sendto(sockfd, packet, sizeof(struct ip) + sizeof(struct tcphdr) + payloadlen, 0, (struct sockaddr *)&din, sizeof(din));
		if( x < 0 ) {
			perror("sendto() error");
			exit(-1);
		}
		//rawprint(packet, packetlen);
	}

	close(sockfd);

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
