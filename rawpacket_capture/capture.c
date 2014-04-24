#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <pcap/pcap.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>

#include "captype.h"
#include "filter.h"

#define LOGFILE "rpcap.log"

#define HTTPCOLOR	"\x1b[46m"
#define PAYLOADCOLOR	"\x1b[41m"
#define NORMALCOLOR	"\x1b[0m"

#define HTTPTEST(REQ, LEN)	( (strncmp((const char *)(packet + hdrlen), (REQ), (LEN)) == 0) \
					&& ((http = memcmp_cont(packet + hdrlen, "HTTP/1.1", 8, payloadlen)) != NULL) )

#define COLORTEST(IDX, STR)	(memcmp(highlight + (IDX), (STR), strlen((STR))) == 0)

static struct linkedlist head; 
static pid_t pid;

static void sighdr(int signo);
static void callback(u_char *filter, const struct pcap_pkthdr *h, const u_char *packet);
static void printfile(uint8_t *flag, const uint8_t *packet, char *payload, const int payloadlen);
static char *gettype(uint16_t type);
static char *getprot(uint8_t prot);
static char *gettos(uint8_t tos);
static char *getflag(uint8_t flag, uint8_t res1, uint8_t res2);
static const uint8_t *memcmp_cont(const uint8_t *pkt, char *target, int targetlen, int pktlen);

int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];
	char *device;
	bpf_u_int32 netptr, maskptr;
	pcap_t *pkt;

	if( signal(SIGINT, (void *)sighdr) == SIG_ERR ) {
		printf("signal(): Failure\n");
		exit(EXIT_FAILURE);
	}

	printf("[main] Start Program\n");
	while( true ) {
		if( (pid = fork()) < 0 ) {
			perror("fork(): ");
			exit(EXIT_FAILURE);

		}else if( pid == 0 ) {
			if( (device = pcap_lookupdev(errbuf)) == NULL ) {
				printf("lookupdev(): %s\n", errbuf);
				exit(EXIT_FAILURE);
			}

			if( pcap_lookupnet(device, &netptr, &maskptr, errbuf) == -1 ) {
				printf("lookupnet(): %s\n", errbuf);
				exit(EXIT_FAILURE);
			}

			if( (pkt = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf)) == NULL ) {
				printf("pcap_open_live(): %s", errbuf);
				exit(EXIT_FAILURE);
			}

			signal(SIGINT, SIG_IGN);  // ignore sigint
			pcap_loop(pkt, 0, callback, NULL);

		}else {
			waitpid(pid, NULL, 0);
			printf("[main] Start capture\n");
		}
	}
}

static void sighdr(int signo)
{
	menu(&head, pid);
}

static void callback(u_char *ignore, const struct pcap_pkthdr *h, const u_char *packet)
{
	struct linkedlist *node = &head;
	const uint8_t *flag, *fltr, *pkt = packet;
	int hdrlen = sizeof(struct ether_header) + sizeof(struct ip);
	int payloadlen = ntohs(*(uint16_t *)&IPLEN(packet)) - sizeof(struct ip);
	int fltrloadlen, i;
	uint8_t extract;

	if( PROTOCOL(pkt) == 6 ) {
		hdrlen += sizeof(struct tcphdr);
		payloadlen -= sizeof(struct tcphdr);

	}else if( PROTOCOL(pkt) == 17 ) {
		hdrlen += sizeof(struct udphdr);
		payloadlen -= sizeof(struct udphdr);
	}
	

	while( node->next != NULL ) {
		node = node->next;
		flag = ((uint8_t *)&node->flag) + 2;
		fltr = ((uint8_t *)&node->data) + 2;
		pkt = packet;

		/* Extract and compare fields byte by btye */
		for(i = 0; i < hdrlen; flag++, pkt++, fltr++, i++) {
			memset(&extract, *flag & *pkt, 1);
			
			if( memcmp(&extract, fltr, 1) != 0 )
				break;
		}

		// No match
		if( i < hdrlen )
			continue;

		/* HTTP Request */
		if( (i = strlen(node->http)) != 0 ) {
			// No match
			if( payloadlen == 0 )
				continue;

			// Find in a payload
			if( memcmp((char *)pkt, node->http, i) == 0 ) {
				while( i++ < payloadlen) {
					if( *(pkt + i) == ' ' ) {
						if( i + 8 < payloadlen && memcmp((char *)(pkt + i + 1), "HTTP/1.1", 8) == 0 )
							break;
						else
							continue;
					}
				}
			}else   continue;

			// Set custom protocol number
			if( strncmp(node->http, "GET", 3) == 0 )
				memset((uint8_t *)packet + 23, 3, 1);
			else if( strncmp(node->http, "PUT", 3) == 0 )
				memset((uint8_t *)packet + 23, 5, 1);
			else// POST
				memset((uint8_t *)packet + 23, 7, 1);
		}

		/* Write to file */
		fltrloadlen = strlen(node->payload);
		if( fltrloadlen == 0 )
			printfile((uint8_t *)&node->flag, packet, NULL, payloadlen);

		else if( payloadlen >= fltrloadlen ) {
			if( memcmp_cont(pkt, node->payload, fltrloadlen, payloadlen) != NULL )
				printfile((uint8_t *)&node->flag, packet, node->payload, payloadlen);
		}
	}
}

/*
 *	Write captured packet to file
 *
 *	uint8_t *flag : filter is set or not
 *	const uint8_t *packet : captured packet
 *	char *fltrload : filter for payload
 *	cosnt int payloadlen : length of captured payload
 */
static void printfile(uint8_t *flag, const uint8_t *packet, char *fltrload, const int payloadlen)
{
	FILE *fp = fopen(LOGFILE, "a");
	const uint8_t *http = NULL;
	char *timestamp;
	struct ether_header *eth;
	struct ip *iphdr;
	struct tcphdr *tcphdr;
	struct udphdr *udphdr;
	uint8_t prot;
	int hdrlen, i;

	flag += 2;  // remove unused member

	eth = (struct ether_header *)packet;
	hdrlen = sizeof(struct ether_header);

	iphdr = (struct ip *)(packet + hdrlen);
	hdrlen += sizeof(struct ip);

	prot = iphdr->ip_p;
	if( prot == 17 ) {
		udphdr = (struct udphdr *)(packet + hdrlen);
		hdrlen += sizeof(struct udphdr);
	}else {
		tcphdr = (struct tcphdr *)(packet + hdrlen);
		hdrlen += sizeof(struct tcphdr);

		// HTTP request check 
		if( PROTOCOL(flag) ) {
			if( prot == 3 ) {
				if( HTTPTEST("GET",3) == false )
					return;

			}else if( prot == 5 ) {
				if( HTTPTEST("PUT",3) == false )
					return;

			}else if(prot == 7) {
				if( HTTPTEST("POST",4) == false )
					return;
			}
		}
	}

	
	

	// Timestamp
	timestamp = (char *)gettime();
	fprintf(fp, "%s ------\n", timestamp);
	free(timestamp);

	/* Ethernet Header */
	i = 0;
	if( DSTMAC(flag) ) {
		fprintf(fp, "\x1b[45mDestination MAC\x1b[0m\t: \x1b[45m");
		while( i < 5 )
			fprintf(fp, "%02X:", eth->ether_dhost[i++]);
		fprintf(fp, "%02X\x1b[0m\n", eth->ether_dhost[i]);
	}else {
		fprintf(fp, "Destination MAC\t: ");
		while( i < 5 )
			fprintf(fp, "%02X:", eth->ether_dhost[i++]);
		fprintf(fp, "%02X\n", eth->ether_dhost[i]);
	}

	i = 0;
	if( SRCMAC(flag) ) {
		fprintf(fp, "\x1b[45mSource MAC\x1b[0m\t: \x1b[45m");
		while( i < 5 )
			fprintf(fp, "%02X:", eth->ether_shost[i++]);
		fprintf(fp, "%02X\x1b[0m\n", eth->ether_shost[i]);
	}else {
		fprintf(fp, "Source MAC\t: ");
		while( i < 5 )
			fprintf(fp, "%02X:", eth->ether_shost[i++]);
		fprintf(fp, "%02X\n", eth->ether_shost[i]);
	}

	if( ETHERTYPE(flag) )
		fprintf(fp, "\x1b[45mEthernet Type\x1b[0m\t: \x1b[45m%s\x1b[0m\n", gettype(eth->ether_type));
	else
		fprintf(fp, "Ethernet Type\t: %s\n", gettype(eth->ether_type));

	/* IP Header */
	if( VERSION(flag) & 0xf0 )
		fprintf(fp, "\x1b[44mVersion\x1b[0m\t\t: \x1b[44m%d\x1b[0m\n", iphdr->ip_v);
	else
		fprintf(fp, "Version\t\t: %d\n", iphdr->ip_v);

	if( IPHLEN(flag) & 0x0f )
		fprintf(fp, "\x1b[44mIP Header length\x1b[0m: \x1b[44m%d\x1b[0m\n", iphdr->ip_hl);
	else
		fprintf(fp, "IP Header length: %d\n", iphdr->ip_hl);

	if( TOS(flag) )
		fprintf(fp, "\x1b[44mType of Service\x1b[0m\t: \x1b[44m%s\x1b[0m\n", gettos(iphdr->ip_tos));
	else
		fprintf(fp, "Type of Service\t: %s\n", gettos(iphdr->ip_tos));

	if( IPLEN(flag) )
		fprintf(fp, "\x1b[44mTotal length\x1b[0m\t: \x1b[44m%d\x1b[0m\n", ntohs(iphdr->ip_len));
	else
		fprintf(fp, "Total length\t: %d\n", ntohs(iphdr->ip_len));

	if( IPID(flag) )
		fprintf(fp, "\x1b[44mIdentification\x1b[0m\t: \x1b[44m%d\x1b[0m\n", ntohs(iphdr->ip_id));
	else
		fprintf(fp, "Identification\t: %d\n", ntohs(iphdr->ip_id));

	if( FRAGMENT(flag) )
		fprintf(fp, "\x1b[44mFragment\x1b[0m\t: \x1b[44m%d\x1b[0m\n", iphdr->ip_off);
	else
		fprintf(fp, "Fragment\t: %d\n", iphdr->ip_off);

	if( TTL(flag) )
		fprintf(fp, "\x1b[44mTime to live\x1b[0m\t: \x1b[44m%d\x1b[0m\n", iphdr->ip_ttl);
	else
		fprintf(fp, "Time to live\t: %d\n", iphdr->ip_ttl);

	if( PROTOCOL(flag) )
		fprintf(fp, "\x1b[44mProtocol\x1b[0m\t: \x1b[44m%s\x1b[0m\n", getprot(iphdr->ip_p));
	else
		fprintf(fp, "Protocol\t: %s\n", getprot(iphdr->ip_p));

	if( IPCKSUM(flag) )
		fprintf(fp, "\x1b[44mChecksum\x1b[0m\t: \x1b[44m%d\x1b[0m\n", ntohs(iphdr->ip_sum));
	else
		fprintf(fp, "Checksum\t: %d\n", ntohs(iphdr->ip_sum));

	if( SRCIP(flag) )
		fprintf(fp, "\x1b[44mSource IP\x1b[0m\t: \x1b[44m%s\x1b[0m\n", inet_ntoa(iphdr->ip_src));
	else
		fprintf(fp, "Source IP\t: %s\n", inet_ntoa(iphdr->ip_src));

	if( DSTIP(flag) )
		fprintf(fp, "\x1b[44mDestination IP\x1b[0m\t: \x1b[44m%s\x1b[0m\n", inet_ntoa(iphdr->ip_dst));
	else
		fprintf(fp, "Destination IP\t: %s\n", inet_ntoa(iphdr->ip_dst));

	if( iphdr->ip_p == 17 ) {
	/* UDP Header */
		if( SRCPORT(flag) )
			fprintf(fp, "\x1b[42mSource Port\x1b[0m\t: \x1b[42m%d\x1b[0m\n", ntohs(udphdr->source));
		else
			fprintf(fp, "Source Port\t: %d\n", ntohs(udphdr->source));

		if( DSTPORT(flag) )
			fprintf(fp, "\x1b[42mDestination Port\x1b[0m: \x1b[42m%d\x1b[0m\n", ntohs(udphdr->dest));
		else
			fprintf(fp, "Destination Port: %d\n", ntohs(udphdr->dest));

		if( UDPLEN(flag) )
			fprintf(fp, "\x1b[42mTotal length\x1b[0m\t: \x1b[42m%d\x1b[0m\n", ntohs(udphdr->len));
		else
			fprintf(fp, "Total length\t: %d\n", ntohs(udphdr->len));

		if( UDPCKSUM(flag) )
			fprintf(fp, "\x1b[42mCheckSum\x1b[0m\t: \x1b[42m%d\x1b[0m\n", ntohs(udphdr->check));
		else
			fprintf(fp, "Checksum\t: %d\n", ntohs(udphdr->check));
	}else {
	/* TCP Header */
		if( SRCPORT(flag) )
			fprintf(fp, "\x1b[31;43mSource Port\x1b[0m\t: \x1b[31;43m%d\x1b[0m\n", ntohs(tcphdr->source));
		else
			fprintf(fp, "Source Port\t: %d\n", ntohs(tcphdr->source));

		if( DSTPORT(flag) )
			fprintf(fp, "\x1b[31;43mDestination Port\x1b[0m: \x1b[31;43m%d\x1b[0m\n", ntohs(tcphdr->dest));
		else
			fprintf(fp, "Destination Port: %d\n", ntohs(tcphdr->dest));

		if( SEQ(flag) )
			fprintf(fp, "\x1b[31;43mSequence Number\x1b[0m\t: \x1b[31;43m%u\x1b[0m\n", ntohl(tcphdr->seq));
		else
			fprintf(fp, "Sequence Number\t: %u\n", ntohl(tcphdr->seq));

		if( ACK(flag) )
			fprintf(fp, "\x1b[31;43mAcknowledgement\x1b[0m\t: \x1b[31;43m%u\x1b[0m\n", ntohl(tcphdr->ack));
		else
			fprintf(fp, "Acknowledgement\t: %u\n", ntohl(tcphdr->ack));

		if( TCPOFF(flag) & 0x0f )
			fprintf(fp, "\x1b[31;43mOffset\x1b[0m\t\t: \x1b[31;43m%d\x1b[0m\n", tcphdr->doff);
		else
			fprintf(fp, "Offset\t\t: %d\n", tcphdr->doff);

		if( TCPRES(flag) & 0xf0 )
			fprintf(fp, "\x1b[31;43mReserved\x1b[0m\t: \x1b[31;43m%d\x1b[0m\n", tcphdr->res1);
		else
			fprintf(fp, "Reserved\t: %d\n", tcphdr->res1);

		char *tmp = getflag(*(packet + 47), tcphdr->res1, tcphdr->res2);
		if( TCPFLAG(flag) )
			fprintf(fp, "\x1b[31;43mFlags\x1b[0m\t\t: \x1b[31;43m%s\x1b[0m\n", tmp);
		else
			fprintf(fp, "Flags\t\t: %s\n", tmp);
		free(tmp);

		if( WINDOW(flag) )
			fprintf(fp, "\x1b[31;43mWindow size\x1b[0m\t: \x1b[31;43m%d\x1b[0m\n", ntohs(tcphdr->window));
		else
			fprintf(fp, "Window size\t: %d\n", ntohs(tcphdr->window));

		if( TCPCKSUM(flag) )
			fprintf(fp, "\x1b[31;43mChecksum\x1b[0m\t: \x1b[31;43m%d\x1b[0m\n", ntohs(tcphdr->check));
		else
			fprintf(fp, "Checksum\t: %d\n", ntohs(tcphdr->check));

		if( URGPTR(flag) )
			fprintf(fp, "\x1b[31;43mUrgent Pointer\x1b[0m\t: \x1b[31;43m%d\x1b[0m\n", ntohs(tcphdr->urg_ptr));
		else
			fprintf(fp, "Urgent Pointer\t: %d\n", ntohs(tcphdr->urg_ptr));
	}

	/* Payload */
	if( fltrload != NULL ) {
		const uint8_t *match = NULL;
		uint8_t highlight[MAXPAYLOAD];
		int fltrloadlen, unmatchlen = 0;
		int colorhex = 0, colorstr = 0;
		int i = 0, str = 0, colorlen = 0, highlen = 0;
		char ch;

		memset(highlight, 0, MAXPAYLOAD);

		packet += hdrlen;
		fltrloadlen = strlen(fltrload);

		fprintf(fp, "*** Payload ***\n");

		if( http != NULL ) {
			if( prot == 3 ) {
				memcpy(highlight, HTTPCOLOR, 5);
				memcpy(highlight + 5, "GET\x1b[0m", 7);
				highlen += 12;
				i += 3;

			}else if( prot == 5 ) {
				memcpy(highlight, HTTPCOLOR, 5);
				memcpy(highlight + 5, "PUT\x1b[0m", 7);
				highlen += 12;
				i += 3;

			}else if( prot == 7 ) {
				memcpy(highlight, HTTPCOLOR, 5);
				memcpy(highlight + 5, "POST\x1b[0m", 8);
				highlen += 13;
				i += 4;
			}
		}

		while( i < payloadlen ) {
			// move to next matching string
			match = memcmp_cont(packet + i, fltrload, fltrloadlen, payloadlen - i);
			if( match == NULL ) {
				unmatchlen = payloadlen - i;

				memcpy(highlight + highlen, packet + i, unmatchlen);
				highlen += unmatchlen;

				break;
			}else {

				if( http != NULL && match - packet > http - packet ) {
				// HTTP/1.1
					unmatchlen = http - (packet + i);

					memcpy(highlight + highlen, packet + i, unmatchlen);
					highlen += unmatchlen;
					i += unmatchlen;

					memcpy(highlight + highlen, "\x1b[46mHTTP/1.1\x1b[0m", 17);
					highlen += 17;
					i += 8;
					http = NULL;
				}else {
					unmatchlen = match - (packet + i);

					memcpy(highlight + highlen, packet + i, unmatchlen);
					highlen += unmatchlen;
					i += unmatchlen;

					memcpy(highlight + highlen, PAYLOADCOLOR, 5);
					highlen += 5;

					memcpy(highlight + highlen, packet + i, fltrloadlen);
					highlen += fltrloadlen;
					i += fltrloadlen;

					memcpy(highlight + highlen, NORMALCOLOR, 4);
					highlen += 4;
				}
			}
		}

		i = 0;
		while( i < highlen ) {
			ch = *(highlight + i);

			if( ch == '\x1b' ) {
				if( COLORTEST(i, PAYLOADCOLOR) == true ) {
					fprintf(fp, PAYLOADCOLOR);
					colorhex = 41;
					i += 5;
					colorlen += 5;
					continue;

				}else if( COLORTEST(i, HTTPCOLOR) == true ) {
					fprintf(fp, HTTPCOLOR);
					colorhex = 46;
					i += 5;
					colorlen += 5;
					continue;

				}else if( COLORTEST(i, NORMALCOLOR) == true ) {
					fprintf(fp, NORMALCOLOR);
					colorhex = 0;
					i += 4;
					colorlen += 4;
					continue;
				}
			}

			fprintf(fp, "%02X ", ch);
			i++;

			if( ++str == 16 ) {
				if( colorhex != 0 )
					fprintf(fp, NORMALCOLOR);

				fprintf(fp, "   ");

				if( colorstr == 41 ) {
					fprintf(fp, PAYLOADCOLOR);
					colorstr = 0;

				}else if( colorstr == 46 ) {
					fprintf(fp, HTTPCOLOR);
					colorstr = 0;
				}

				while( colorlen > 0 ) {
					ch = *(highlight + i - colorlen - str);
					if( ch > 126 || ch < 32 ) {
						if( ch == 27 ) {
							if( COLORTEST(i - colorlen - str, PAYLOADCOLOR) == true )
								colorstr = 41;

							else if( COLORTEST(i - colorlen - str, HTTPCOLOR) == true )
								colorstr = 46;

							else if( COLORTEST(i - colorlen - str, NORMALCOLOR) == true )
								colorstr = 0;

							else
								ch = '.';
						}else
							ch = '.';
					}
					fprintf(fp, "%c", ch);
					colorlen--;
				}

				while( str > 0 ) {
					ch = *(highlight + i - str);
					if( ch > 126 || ch < 32 ) {
						if( ch == 27 ) {
							if( COLORTEST(i - colorlen - str, PAYLOADCOLOR) == true )
								colorstr = 41;
							else if( COLORTEST(i - colorlen - str, HTTPCOLOR) == true )
								colorstr = 46;
							else if( COLORTEST(i - colorlen - str, NORMALCOLOR) == true )
								colorstr = 0;
							else
								ch = '.';
						}else
							ch = '.';
					}
					fprintf(fp, "%c", ch);
					str--;
				}

				if( colorstr != 0 )
					fprintf(fp, NORMALCOLOR);

				fprintf(fp, "\n");

				if( colorhex == 41 ) {
					fprintf(fp, PAYLOADCOLOR);
					colorhex = 0;

				}else if( colorhex == 46 ) {
					fprintf(fp, HTTPCOLOR);
					colorhex = 0;
				}
			}
		}

		if( str != 0 ) {
			int padd = 17;
			if( colorhex != 0 )
				fprintf(fp, NORMALCOLOR);

			while( str < padd-- )
				fprintf(fp, "   ");

			if( colorstr == 41 ) {
				fprintf(fp, PAYLOADCOLOR);
				colorstr = 0;

			}else if( colorstr == 46 ) {
				fprintf(fp, HTTPCOLOR);
				colorstr = 0;
			}

			while( colorlen > 0 ) {
				ch = *(highlight + i - colorlen - str);
				if( ch > 126 || ch < 32 ) {
					if( ch == 27 ) {
						if( COLORTEST(i - colorlen - str, PAYLOADCOLOR) == true )
							colorstr = 41;
						else if( COLORTEST(i - colorlen - str, HTTPCOLOR) == true )
							colorstr = 46;
						else if( COLORTEST(i - colorlen - str, NORMALCOLOR) == true )
							colorstr = 0;
						else
							ch = '.';
					}else
						ch = '.';
				}
				fprintf(fp, "%c", ch);
				colorlen--;
			}

			while( str > 0 ) {
				ch = *(highlight + i - str);
				if( ch > 126 || ch < 32 ) {
					if( ch == 27 ) {
						if( COLORTEST(i - colorlen - str, PAYLOADCOLOR) == true )
							colorstr = 41;
						else if( COLORTEST(i - colorlen - str, HTTPCOLOR) == true )
							colorstr = 46;
						else if( COLORTEST(i - colorlen - str, NORMALCOLOR) == true )
							colorstr = 0;
						else
							ch = '.';
					}else
						ch = '.';
				}
				fprintf(fp, "%c", ch);
				str--;
			}
			fprintf(fp, "\x1b[0m\n");
		}
	}else { // fltrload == NULL
		uint8_t highlight[MAXPAYLOAD];
		int unmatchlen = 0;
		int colorhex = 0, colorstr = 0;
		int i = 0, str = 0, colorlen = 0, highlen = 0;
		char ch;

		memset(highlight, 0, MAXPAYLOAD);

		packet += hdrlen;

		fprintf(fp, "*** Payload ***\n");

		if( http != NULL ) {
			if( prot == 3 ) {
				memcpy(highlight, HTTPCOLOR, 5);
				memcpy(highlight + 5, "GET\x1b[0m", 7);
				highlen += 12;
				i += 3;

			}else if( prot == 5 ) {
				memcpy(highlight, HTTPCOLOR, 5);
				memcpy(highlight + 5, "PUT\x1b[0m", 7);
				highlen += 12;
				i += 3;

			}else if( prot == 7 ) {
				memcpy(highlight, HTTPCOLOR, 5);
				memcpy(highlight + 5, "POST\x1b[0m", 8);
				highlen += 13;
				i += 4;
			}
		}

		while( i < payloadlen ) {
		// move to next matching string
			if( http != NULL ) {
			// HTTP/1.1
				unmatchlen = http - (packet + i);

				memcpy(highlight + highlen, packet + i, unmatchlen);
				highlen += unmatchlen;
				i += unmatchlen;

				memcpy(highlight + highlen, "\x1b[46mHTTP/1.1\x1b[0m", 17);
				highlen += 17;
				i += 8;
				http = NULL;
			}else {
				memcpy(highlight + highlen, packet + i, payloadlen - i);
				highlen += unmatchlen;
				i += unmatchlen;
			}
		}

		i = 0;
		while( i < highlen ) {
			ch = *(highlight + i);

			if( ch == '\x1b' ) {
				if( COLORTEST(i, PAYLOADCOLOR) == true ) {
					fprintf(fp, PAYLOADCOLOR);
					colorhex = 41;
					i += 5;
					colorlen += 5;
					continue;

				}else if( COLORTEST(i, HTTPCOLOR) == true ) {
					fprintf(fp, HTTPCOLOR);
					colorhex = 46;
					i += 5;
					colorlen += 5;
					continue;

				}else if( COLORTEST(i, NORMALCOLOR) == true ) {
					fprintf(fp, NORMALCOLOR);
					colorhex = 0;
					i += 4;
					colorlen += 4;
					continue;
				}
			}

			fprintf(fp, "%02X ", ch);
			i++;

			if( ++str == 16 ) {
				if( colorhex != 0 )
					fprintf(fp, NORMALCOLOR);

				fprintf(fp, "   ");

				if( colorstr == 41 ) {
					fprintf(fp, PAYLOADCOLOR);
					colorstr = 0;

				}else if( colorstr == 46 ) {
					fprintf(fp, HTTPCOLOR);
					colorstr = 0;
				}

				while( colorlen > 0 ) {
					ch = *(highlight + i - colorlen - str);
					if( ch > 126 || ch < 32 ) {
						if( ch == 27 ) {
							if( COLORTEST(i - colorlen - str, PAYLOADCOLOR) == true )
								colorstr = 41;
							else if( COLORTEST(i - colorlen - str, HTTPCOLOR) == true )
								colorstr = 46;
							else if( COLORTEST(i - colorlen - str, NORMALCOLOR) == true )
								colorstr = 0;
							else
								ch = '.';
						}else
							ch = '.';
					}
					fprintf(fp, "%c", ch);
					colorlen--;
				}

				while( str > 0 ) {
					ch = *(highlight + i - str);
					if( ch > 126 || ch < 32 ) {
						if( ch == 27 ) {
							if( COLORTEST(i - colorlen - str, PAYLOADCOLOR) == true )
								colorstr = 41;
							else if( COLORTEST(i - colorlen - str, HTTPCOLOR) == true )
								colorstr = 46;
							else if( COLORTEST(i - colorlen - str, NORMALCOLOR) == true )
								colorstr = 0;
							else
								ch = '.';
						}else
							ch = '.';
					}
					fprintf(fp, "%c", ch);
					str--;
				}

				if( colorstr != 0 )
					fprintf(fp, NORMALCOLOR);

				fprintf(fp, "\n");

				if( colorhex == 41 ) {
					fprintf(fp, PAYLOADCOLOR);
					colorhex = 0;

				}else if( colorhex == 46 ) {
					fprintf(fp, HTTPCOLOR);
					colorhex = 0;
				}
			}
		}

		if( str != 0 ) {
			int padd = 17;
			if( colorhex != 0 )
				fprintf(fp, NORMALCOLOR);

			while( str < padd-- )
				fprintf(fp, "   ");

			if( colorstr == 41 ) {
				fprintf(fp, PAYLOADCOLOR);
				colorstr = 0;

			}else if( colorstr == 46 ) {
				fprintf(fp, HTTPCOLOR);
				colorstr = 0;
			}

			while( colorlen > 0 ) {
				ch = *(highlight + i - colorlen - str);
				if( ch > 126 || ch < 32 ) {
					if( ch == 27 ) {
						if( COLORTEST(i - colorlen - str, PAYLOADCOLOR) == true )
							colorstr = 41;
						else if( COLORTEST(i - colorlen - str, HTTPCOLOR) == true )
							colorstr = 46;
						else if( COLORTEST(i - colorlen - str, NORMALCOLOR) == true )
							colorstr = 0;
						else
							ch = '.';
					}else
						ch = '.';
				}
				fprintf(fp, "%c", ch);
				colorlen--;
			}

			while( str > 0 ) {
				ch = *(highlight + i - str);
				if( ch > 126 || ch < 32 ) {
					if( ch == 27 ) {
						if( COLORTEST(i - colorlen - str, PAYLOADCOLOR) == true )
							colorstr = 41;
						else if( COLORTEST(i - colorlen - str, HTTPCOLOR) == true )
							colorstr = 46;
						else if( COLORTEST(i - colorlen - str, NORMALCOLOR) == true )
							colorstr = 0;
						else
							ch = '.';
					}else
						ch = '.';
				}
				fprintf(fp, "%c", ch);
				str--;
			}
			fprintf(fp, "\x1b[0m\n");
		}
	}
	fprintf(fp, "----------------------------\n");
	fclose(fp);
}

// Ethernet Type (Ethernet Header)
// Adjust Little Endian
static char *gettype(uint16_t type)
{
	switch(type) {
		case 0x0008: return "IP";

		// Not for HW
		case 0x0002: return "Xerox PUP";
		case 0x0005: return "Sprite";
		case 0x0608: return "ARP";
		case 0x3580: return "Reverse ARP";
		case 0x9B80: return "Apple Talk";
		case 0xF380: return "Apple Talk ARP";
		case 0x0081: return "VLAN";
		case 0x3781: return "IPX";
		case 0xDD86: return "IPv6";
		case 0x0090: return "Loop back";
	};

	return "";
}

// Protocol (IP Header)
static char *getprot(uint8_t prot)
{
	switch(prot) {
		case   6: return "TCP";
		case  17: return "UDP";
		case   3: return "HTTP(GET)";   // custom
		case   5: return "HTTP(PUT)";   // custom
		case   7: return "HTTP(POST)";  // custom

		// Not for HW
		case   0: return "Hop";
		case   1: return "ICMP";
		case   2: return "IGMP";
		case   4: return "IPIP";
		case   8: return "EGP";
		case  12: return "PUP";
		case  22: return "IDP";
		case  29: return "TPC4";
		case  33: return "DCCP";
		case  41: return "IPv6";
		case  43: return "Route";
		case  44: return "Fragment";
		case  46: return "RSVP";
		case  47: return "GRE";
		case  50: return "ESP";
		case  51: return "AH";
		case  58: return "ICMPv6";
		case  59: return "None";
		case  60: return "DSTOPTS";
		case  92: return "MTP";
		case  98: return "Encap";
		case 103: return "PIM";
		case 108: return "COMP";
		case 132: return "SCTP";
		case 136: return "UDP-Lite";
		case 255: return "Raw";
	};

	return "";
}

// Type of Service (IP Header)
static char *gettos(uint8_t tos)
{
	switch(tos) {
		case  0: return "Routine";

		// Not for HW
		case  1: return "Priority";
		case  2: return "Immediate";
		case  3: return "Flash";
		case  4: return "Override";
		case  5: return "Critical";
		case  6: return "Internetwork";
		case  7: return "Network";
		case  8: return "Minimum Delay";
		case 16: return "Maximum Throughput";
		case 32: return "Maximum Reliability";
		case 64: return "Minimum Cost";
	};

	return "";
}

// TCP Flags (TCP Header)
// Adjus Little Endian
static char *getflag(uint8_t flag, uint8_t res1, uint8_t res2)
{
	char *buf = (char *)malloc(27);
	if( buf == NULL ) {
		perror("malloc(): ");
		return NULL;
	}
	memset(buf, 0, 27);

	if( flag & 0x01 ) strncat(buf, "FIN ", 4);
	if( flag & 0x02 ) strncat(buf, "SYN ", 4);
	if( flag & 0x04 ) strncat(buf, "RST ", 4);
	if( flag & 0x08 ) strncat(buf, "PSH ", 4);
	if( flag & 0x10 ) strncat(buf, "ACK ", 4);
	if( flag & 0x20 ) strncat(buf, "URG ", 4);

	// Not for HW
	if( res1 & 0x8  ) strncat(buf, "NS ",  3);
	if( res2 & 0x1  ) strncat(buf, "CWR ", 4);
	if( res2 & 0x2  ) strncat(buf, "ECE ", 4);

	return buf;
}

/*
 *	Do string match for a payload
 *	If perfect match is not found in a block, adjust start character of word
 *	  to the nearest matched character.
 *
 *	e.g.  AABAABAB   ->   AABAABAB
 *	      BAAB              BAAB
 */	      
static const uint8_t *memcmp_cont(const uint8_t *pkt, char *target, int targetlen, int pktlen)
{
	int perfect, nearest, j, i = 0;
	while( i + targetlen <= pktlen ) {
		perfect = j = 0;
		nearest = targetlen;

		do {    // move to nearest matched character
			if( (nearest % targetlen == 0) && (*(pkt + i + j) == *target) )
				nearest = j;

			if( *(pkt + i + j) == *(target + j) )
				perfect++;

		}while( (++j < targetlen) && (i + j < pktlen) );

		if( perfect == targetlen )
			return pkt + i;

		i += (nearest != 0) ? nearest : targetlen;  // 0 : first character is matched
	}

	return NULL;
}
