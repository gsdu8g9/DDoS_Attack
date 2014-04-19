#include <netinet/in.h>
#include "hdr.h"

#define IPPROTO_HTTP_GET	5
#define IPPROTO_HTTP_POST	7

struct packet_in
{
	uint8_t protocol;
	uint16_t sport;
	uint16_t dport;
	struct in_addr sip, dip;
};

struct rawpacket_flag
{
	uint8_t res1:1;		// 0x01
	uint8_t sip:1;		// 0x02
	uint8_t sport:1;	// 0x04
	uint8_t dip:1;		// 0x08
	uint8_t dport:1;	// 0x10
	uint8_t protocol:1;	// 0x20
	uint8_t payload:1;	// 0x40
	uint8_t res2:1;		// 0x80
};


int packet_send(struct packet_in *pkt, char *payload, uint16_t payloadlen);
void random_input(struct packet_in *pkt);
void fill_input(struct packet_in *pkt, struct rawpacket_flag *flag);
char *payload_create(uint16_t *payloadlen, uint8_t protocol);
