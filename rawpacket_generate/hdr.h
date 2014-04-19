#include <sys/types.h>
#include <netinet/ip.h>

bool ether_create(struct ether_header *eth, int rawsockfd)
bool iphdr_create(struct ip *iphdr, uint16_t dip, TYPE type, int payloadlen);
bool tcphdr_create(struct tcphdr *tcphdr, uint16_t dport, TYPE type, char *payload, uint16_t payloadlen, struct ip *iphdr);
bool udphdr_create(struct udphdr *udphdr, uint16_t dport, char *payload, uint16_t payloadlen, struct ip *iphdr);
