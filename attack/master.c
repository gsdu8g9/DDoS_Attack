#include <stdio.h>
#include <string.h>	   // strtok()
#include <stdlib.h>	   // exit(), EXIT_FAILURE
#include <arpa/inet.h>	   // inet_aton(), inet_ntoa()
#include <netinet/in.h>	   // struct in_addr
#include <arpa/inet.h>

#include "slave.h"

int main()
{
	struct Flow flow;
	char *token, *cmd;
	char buf[50];
	int i;

	while( 1 ) {
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
		flow.times = atoi(strtok(NULL, " "));

		//printf("%s %d %d %d\n", inet_ntoa(flow.ip), flow.port, flow.times, flow.type);
		/* Command */
		if( strncmp(cmd, "start", 5) == 0 ) {
			if( slave_create(&flow) == false) {
				printf("slave_create(): Failure\n");
			}

		}else if( strncmp(cmd, "stop", 4) == 0 ) {
			if( slave_delete(&flow) == false ) {
				printf("slave_delete(): Failure\n");
			}

		}else if( strncmp(cmd, "finish", 6) == 0 ) {
			slave_deleteall();
			exit(EXIT_SUCCESS);

		}else {
			printf("Wrong Command: %s\n", cmd);
			printf("Ignore Current Commands\n");
		}
	}
}
