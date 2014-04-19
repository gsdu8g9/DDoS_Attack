#ifndef __SLAVE_H__
#define __SALVE_H__

#include <netinet/in.h>		// struct in_addr

typedef unsigned char bool;
typedef unsigned short uint16_t;
typedef unsigned long int uint64_t;

typedef enum {SYN, FIN, UDP} TYPE;

#define false 0
#define true 1

#define PAYLOADLEN 1500

struct Flow {
	struct in_addr ip;
	uint16_t port;
	uint16_t times;
	TYPE type;
};

struct SlaveTable {
	struct Flow flow;
	pthread_t *tid;
	struct SlaveTable *next;
};

bool slave_create(struct Flow flow);
bool slave_delete(struct Flow flow);
void slave_deleteall();

#endif
