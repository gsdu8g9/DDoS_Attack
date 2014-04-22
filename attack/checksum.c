#include <sys/types.h>		// uint16_t
#include <netinet/ip.h>		// struct ip
#include <netinet/tcp.h>	// struct tcphdr
#include <netinet/udp.h>	// struct udphdr
#include <string.h>		// memcpy()

//#include "raw_packet.h"
uint16_t checksum(uint16_t *ptr, int len)
{
	uint16_t *tmp = ptr;
	int cksum = 0;

	while( len > 1 ) {
		cksum += *tmp++;
		len -= sizeof(uint16_t);  // 2
	}

	// Adjust to 16-bit
	if( len == 1 )
		cksum += (uint16_t)(*(uint8_t *)tmp);

	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += cksum >> 16;

	return (uint16_t)~cksum;
}

uint16_t tcp_checksum(struct ip *iphdr, struct tcphdr *tcphdr, char *payload, uint16_t payloadlen)
{
	char cksum[IP_MAXPACKET];
	char *ptr = cksum;
	int len, cksumlen = 0;

	len = sizeof(iphdr->ip_src.s_addr);
	memcpy(ptr, &iphdr->ip_src.s_addr, len); 
	cksumlen += len;
	ptr += len;

	len = sizeof(iphdr->ip_dst.s_addr);
	memcpy(ptr, &iphdr->ip_dst.s_addr, len);
	cksumlen += len;
	ptr += len;

	*ptr = 0;
	ptr++;
	cksumlen++;

	len = sizeof(iphdr->ip_p);
	memcpy(ptr, &iphdr->ip_p, len);
	cksumlen += len;
	ptr += len;

	int tcphdrlen = sizeof(struct tcphdr);
	uint16_t tmp = htons(tcphdrlen + payloadlen);
	len = sizeof(tmp);
	memcpy(ptr, &tmp, len);
	cksumlen += len;
	ptr += len;

	memcpy(ptr, tcphdr, tcphdrlen);
	cksumlen += tcphdrlen;

	if( payloadlen != 0 ) {
		ptr += tcphdrlen;
		memcpy(ptr, payload, payloadlen);
		cksumlen += payloadlen;

		int i = 0;
		while( (payloadlen + i++)%2 )
			cksumlen++;
	}

	return checksum((uint16_t *)cksum, cksumlen);
}

uint16_t udp_checksum(struct ip *iphdr, struct udphdr *udphdr, char *payload, uint16_t payloadlen)
{
	char cksum[IP_MAXPACKET];
	char *ptr = cksum;
	int len, cksumlen = 0;

	len = sizeof(iphdr->ip_src.s_addr);
	memcpy(ptr, &iphdr->ip_src.s_addr, len); 
	cksumlen += len;
	ptr += len;

	len = sizeof(iphdr->ip_dst.s_addr);
	memcpy(ptr, &iphdr->ip_dst.s_addr, len);
	cksumlen += len;
	ptr += len;

	*ptr = 0;
	ptr++;
	cksumlen++;

	len = sizeof(iphdr->ip_p);
	memcpy(ptr, &iphdr->ip_p, len);
	cksumlen += len;
	ptr += len;

	len = sizeof(udphdr->len);
	memcpy(ptr, &udphdr->len, len);
	cksumlen += len;
	ptr += len;

	len = sizeof(udphdr);
	memcpy(ptr, udphdr, len);
	cksumlen += len;

	if( payloadlen != 0 ) {
		ptr += len;
		memcpy(ptr, payload, payloadlen);
		cksumlen += len;

		int i = 0;
		while( (payloadlen + i++)%2 )
			cksumlen++;
	}

	return checksum((uint16_t *)cksum, cksumlen);
}
