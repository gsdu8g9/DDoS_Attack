#ifndef __THREADPOOL_H__
#define __THREADPOOL_H__

#include <netinet/in.h>

/* header */
typedef unsigned char bool;

struct Flow {
	struct in_addr ip;
	uint16_t port;
	uint8_t type;
	uint8_t unused;
};

struct SlaveTable {
	struct Flow flow;
	int botfd;
	bool flag;  // 0: free. 1: busy
};

void thread_init(int fd[]);
int thread_regist(struct Flow flow, int times);
int thread_free(struct Flow flow, int times);

// DEBUG
void thread_info();

#endif
