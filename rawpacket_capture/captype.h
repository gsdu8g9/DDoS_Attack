#ifndef __CAPTYPE_H__
#define __CAPTYPE_H__ 1

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define MAXFILENAME 100
#define MAXPAYLOAD  1000

typedef unsigned char bool;
#define false 0
#define true  1

struct dumpkt {
	char unused[2];
	struct ether_header ethdr;
	struct ip iphdr;
	union {
		struct tcphdr tcp;
		struct udphdr udp;
	} hdr;
};

struct linkedlist {
	struct dumpkt data;
	struct dumpkt flag;
	char http[5];
	char file[MAXFILENAME];
	char payload[MAXPAYLOAD];
	struct linkedlist *next;
};

struct linkedlist *alloc_node(const char * const filename);

#endif
