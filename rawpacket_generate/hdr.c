#include <stdio.h>
#include <stdlib.h>
#include <string.h>		// memset(), strncpy()
#include <time.h>
#include <errno.h>		// perror()
#include <sys/ioctl.h>		// ioctl(), SIOCGIFHWADDR
#include <net/if.h>		// struct ifreq
#include <net/ethernet.h>	// struct ether_header
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>		// htons(), inet_pton()

#include "hdr.h"
#include "checksum.h"

bool iphdr_create(struct ip *iphdr)
{
	iphdr->ip_id = rand();
	iphdr->ip_src = rand();
	iphdr->ip_sum = 0;

	iphdr->ip_sum = checksum((uint16_t *)iphdr, sizeof(struct ip));

	return true;
}

bool tcphdr_create(struct tcphdr *tcphdr, char *payload, uint16_t payloadlen, struct ip *iphdr)
{
	tcphdr->source = rand();
	tcphdr->seq = rand();
	tcphdr->ack_seq = rand();
	tcphdr->check = 0;

	tcphdr->check = tcp_checksum(iphdr, tcphdr, payload, payloadlen);

	return true;
}

bool udphdr_create(struct udphdr *udphdr, char *payload, uint16_t payloadlen, struct ip *iphdr)
{
	udphdr->source = rand();
	udphdr->check = 0;

	udphdr->check = udp_checksum(iphdr, udphdr, payload, payloadlen);

	return true;
}
