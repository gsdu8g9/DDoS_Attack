#include <stdio.h>	// printf(), perror()
#include <unistd.h>	// write()
#include <string.h>	// memcpy(), memcmp()

#include "threadpool.h"

/* body */
static struct SlaveTable threadpool[16];

static void threadpool_push(int fd);
static int threadpool_pop();
static int threadpool_search(struct Flow flow);
static void threadpool_update(int fd, struct Flow flow);


void thread_init(int fd[])
{
	int i;
	for(i = 0; i < 16; i++) {
		threadpool[i].botfd = fd[i];
		threadpool[i].flag = 0;
	}
}

static void threadpool_push(int fd)
{
	int i;
	for(i = 0; i < 16; i++) {
		if( threadpool[i].botfd == fd ) {
			threadpool[i].flag = 0;
			break;
		}
	}
}

static int threadpool_pop()
{
	int i;
	for(i = 0; i < 16; i++) {
		if( threadpool[i].flag == 0 ) {
			threadpool[i].flag = 1;
			return threadpool[i].botfd;
		}
	}

	return -1;
}

int thread_regist(struct Flow flow, int times)
{
	int fd, i;
	int count = 0;

	for(i = 0; i < times; i++) {
		if( (fd = threadpool_pop()) < 0 ) {
			printf("There is no free slave\n");
			break;
		}else {
			if( write(fd, (char *)&flow, sizeof(struct Flow)) < 0 ) {
				perror("write()");
				threadpool_push(fd);

			}else {
				threadpool_update(fd, flow);
				count++;
			}
		}
	}

	return count;
}

static void threadpool_update(int fd, struct Flow flow)
{
	int i;
	for(i = 0; i < 16; i++) {
		if( threadpool[i].botfd == fd ) {
			memcpy(&threadpool[i].flow, &flow, sizeof(struct Flow));
			break;
		}
	}
}

int thread_free(struct Flow flow, int times)
{
	int fd, i;
	int count = 0;

	for(i = 0; i < times; i++) {
		if( (fd = threadpool_search(flow)) < 0 ) {
			printf("There is no matched slave\n");
			break;
		}else {
			if( write(fd, (char *)&flow, sizeof(struct Flow)) < 0 ) {
				perror("write()");
				threadpool_pop(fd);

			}else {
				threadpool_push(fd);
				count++;
			}
		}
	}

	return count;
}

static int threadpool_search(struct Flow flow)
{
	int i;
	for(i = 0; i < 16; i++) {
		if( threadpool[i].flag == 1 && memcmp(&threadpool[i].flow, &flow, sizeof(struct Flow)) == 0 )
			return threadpool[i].botfd;
	}

	return -1;
}

// DEBUG
void thread_info()
{
	int i;
	int count = 0;
	for(i = 0; i < 16; i++) {
		if( threadpool[i].flag == 0 ) count++;
	}

	printf("[*] %d slaves remain\n", count);
}
