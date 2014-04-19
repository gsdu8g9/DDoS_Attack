#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <netinet/in.h>       // IPPROTO_RAW, IPPROTO_IP, IPPROTO_TCP, INET_ADDRSTRLEN
#include <arpa/inet.h>
#include <signal.h>

#include "generator.h"

void sighdr(int signo);
int isCharChar(char ch);
int parameter_check(int type, const char * const arg);

static int cnt = 0, total = 0;

int main(int argc, char *argv[])
{
	printf("Good Luck :)\n");

	int param, num = 1, i = 0;
	char *src, *dst, proto[4], *payload, *rand_payload;
	struct packet_in input;
	struct rawpacket_flag flag;
	uint16_t payloadlen = 0, rand_payloadlen;
	bool inf = false, http = false;

	memset(&flag , 0, sizeof(struct rawpacket_flag));
	memset(&input, 0, sizeof(struct packet_in));

	while( (param = getopt(argc, argv, "d:s:t:l:n:f")) != -1 ) {
		switch(param) {
			case 's':
				flag.sip = flag.sport = true;
				src = optarg;
				break;
			case 'd':
				flag.dip = flag.dport = true;
				dst = optarg;
				break;
			case 't':
				flag.protocol = true;
				strncpy(proto, optarg, 4);
				break;
			case 'l':
				flag.payload = true;
				payload = optarg;
				payloadlen = strlen(payload);
				break;
			case 'n':
				num = atoi(optarg);
				break;
			case 'f':
				inf = true; num++;
				break;
			case '?':
				printf("Ignore this option: %c\n", optopt);
		}
	}

	if( *(char *)&flag == 0 ) {
		printf("Usage: sudo ./generator [-d dst_ip:dst_port] [-s src_ip:src_port]\n\t\t\t[-t protocol] [-l payload]\n\t\t\t[-n number_of_packet] [-f]\n");
		exit(EXIT_FAILURE);
	}

	if( !flag.dip ) {
		printf("You should enter destination ip\n");
		exit(EXIT_FAILURE);
	}

	/* Check Source Parameter */
	if( flag.sip ) {
		if( (i = parameter_check(HOST, src)) < 0 ) {
			printf("Invalid Source Infomation: %s\n", src);
			printf("Skip this option\n");
			flag.sip = flag.sport = false;
		}else {
			if( i == 0 ) {  // random ip
				input.sport = atoi(src + i + 1);
				flag.sip = false;
			}else {
				if( strlen(src) - i == 1 )  // random port
					flag.sport = false;
				else
					input.sport = atoi(src + i + 1);

				src[i] = '\0';
				if( inet_pton(AF_INET, src, &(input.sip)) != 1 ) {
					perror("inet_pton() failure: ");
					exit(EXIT_FAILURE);
				}
			}
		}
	}

	/* Check Destination Parameter */
	if( flag.dip ) {
		if( (i = parameter_check(HOST, dst)) < 0 ) {
			printf("Invalid Source Infomation: %s\n", dst);
			printf("Skip this option\n");
			flag.dip = flag.dport = false;
		}else {
			if( i == 0 ) {  // random ip
				input.dport = atoi(dst + i + 1);
				flag.dip = false;
			}else {
				if( strlen(dst) - i == 1 )  // random port
					flag.dport = false;
				else
					input.dport = atoi(dst + i + 1);

				dst[i] = '\0';
				if( inet_pton(AF_INET, dst, &(input.dip)) != 1 ) {
					perror("inet_pton() failure: ");
					exit(EXIT_FAILURE);
				}
			}
		}
	}

	/* Check Protocol Parameter */
	if( flag.protocol ) {
		if( (i = parameter_check(PROTOCOL, proto)) < 0 ) {
			printf("Invalid Protocol Information: %s\n", proto);
			printf("Skip this option\n");
			flag.protocol = false;
		}else {
			input.protocol = (uint8_t)i;
		}
	}

	/* Test Start!! */
	signal(SIGINT, (void *)sighdr);
	for(i = 0; i < num; i++, total++) {
		srand(time(NULL));
		 
		if( num == 1 || rand()%20 == 0 ) {  // target
			printf("Call fill_input(): %d\n", total);

			fill_input(&input, &flag);

			if( flag.payload == false ) {
				payload = payload_create(&payloadlen, input.protocol);
			}else {
				if( input.protocol == IPPROTO_HTTP_GET ) {
					http = true;
					char *tmp = (char *)malloc(payloadlen);
					memcpy(tmp, payload, payloadlen);

					payload = (char *)malloc(payloadlen + 15);
					memcpy(payload, "GET / HTTP/1.1\n", 15);
					memcpy(payload+15, tmp, payloadlen);
					payloadlen += 15;

					free(tmp);
				}else if( input.protocol == IPPROTO_HTTP_POST ) {
					http = true;
					char *tmp = (char *)malloc(payloadlen);
					memcpy(tmp, payload, payloadlen);

					payload = (char *)malloc(payloadlen + 16);
					memcpy(payload, "POST / HTTP/1.1\n", 16);
					memcpy(payload+16, tmp, payloadlen);
					payloadlen += 16;

					free(tmp);
				}
			}

			if( input.protocol == IPPROTO_HTTP_GET || input.protocol == IPPROTO_HTTP_POST )
				input.protocol = IPPROTO_TCP;

			if( packet_send(&input, payload, payloadlen) < 0 )
				printf("Fail to send %dth packet\n", i);

			if( flag.payload == false || http == true ) {
				free(payload);
				http = false;
			}
			cnt++;
		}else {
			struct packet_in randpkt;

			memcpy(&randpkt.dip.s_addr, &input.dip.s_addr, sizeof(input.dip.s_addr));

			random_input(&randpkt);

			rand_payload = payload_create(&rand_payloadlen, randpkt.protocol);

			if( randpkt.protocol == IPPROTO_HTTP_GET || randpkt.protocol == IPPROTO_HTTP_POST )
				randpkt.protocol = IPPROTO_TCP;

			if( packet_send(&randpkt, rand_payload, rand_payloadlen) < 0 )
				printf("Fail to send %dth packet\n", i);

			if( rand_payloadlen != 0 )
				free(rand_payload);
		}

		if( inf == true ) i = 0;
		//usleep(10000);
		sleep(2);
	}

	exit(EXIT_SUCCESS);
}

void sighdr(int signo)
{
	printf("\n\nYou should capture %d packets from %d\n\n", cnt, total);
	exit(EXIT_SUCCESS);
}

int isCharChar(char ch)
{
	return (ch < '0' || ch > '9');
}

int parameter_check(int type, const char * const arg)
{
	if( type == HOST ) {
		int len = strlen(arg);
		int ipcheck = 0;
		int i = 0;

		while( i < len ) {
			if( arg[i] == ':' )
				break;
			else if( arg[i] == '.' )
				ipcheck++;
			else if( isCharChar(arg[i]) )
				return -1;
			i++;
		}

		if( i == len )
			return -1;

		if( i != 0 && (ipcheck != 3 || i < 7 ) )
			return -1;

		int divide = i++;

		while(i < len) {
			if( isCharChar(arg[i]) )
				return -1;
			i++;
		}

		return divide;

	}else if( type == PROTOCOL ) {
		if( strncmp(arg, "ip", 2) == 0 )
			return IPPROTO_IP;

		else if( strncmp(arg, "tcp", 3) == 0 )
			return IPPROTO_TCP;

		else if( strncmp(arg, "udp", 3) == 0 )
			return IPPROTO_UDP;

		else if( strncmp(arg, "get", 3) == 0 )
			return IPPROTO_HTTP_GET;

		else if( strncmp(arg, "post", 4) == 0 )
			return IPPROTO_HTTP_POST;
		else
			return -1;
	}

	return -1;
}
