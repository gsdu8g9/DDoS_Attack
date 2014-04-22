#include <sys/types.h>		// uint16_t
#include <netinet/ip.h>		// struct ip
#include <netinet/tcp.h>	// struct tcphdr
#include <netinet/udp.h>	// struct udphdr

uint16_t checksum(uint16_t *ptr, int len);
uint16_t tcp_checksum(struct ip *iphdr, struct tcphdr *tcphdr, char *payload, uint16_t payloadlen);
uint16_t udp_checksum(struct ip *iphdr, struct udphdr *udphdr, char *payload, uint16_t payloadlen);
