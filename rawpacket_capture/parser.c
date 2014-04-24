#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "captype.h"
#include "parser.h"

static bool http = false;

static bool setMAC(uint8_t * const flag, uint8_t *host, const char * const buf);
static bool setIP(struct in_addr * const flag, struct in_addr *ip, const char * const buf);
static uint16_t setPORT(uint16_t * const flag, const char * const buf);

static uint8_t setFlag8_t(bool loop, uint8_t * const flag, const char * const buf);
static uint16_t setFlag16_t(bool loop, uint16_t * const flag, const char * const buf);
static bool setFlags(struct tcphdr * const flag, struct tcphdr *data, const char * const buf);

static uint8_t setNum8_t(uint8_t * const flag, const char * const buf);
static uint16_t setNum16_t(uint16_t * const flag, const char * const buf);
static uint32_t setNum32_t(uint32_t * const flag, const char * const buf);
static uint8_t setNum4_t(bool push, uint8_t * const flag, const char * const buf);

static uint16_t setHex16_t(uint16_t * const flag, const char * const buf);

inline int errform(const char * const buf)
{
	printf("Format Error: %s (ignored)\n", buf);
	return 0;
}

inline int overflow(const char * const buf)
{
	printf("Overflow: %s (ignored)\n", buf);
	return 0;
}

void parse(FILE *fp, struct linkedlist *node)
{
	char buf[MAXPAYLOAD];
	const int num = 29;
	int ch, i = 0;

	while( i++ < num ) {
		// move to next parameter
		while( (ch = fgetc(fp)) != EOF ) {
			if( ch == ':' ) {
				if( fgetc(fp) == ' ' )
					break;

				if( fseek(fp, -1, SEEK_CUR) < 0 )
					perror("fseek(): ");
			}
		}

		fgets(buf, MAXPAYLOAD, fp);

		if( buf[0] == '\n' )  // just enter
			continue;
		else
			buf[strlen(buf) - 1] = '\0';

		/* Etherent Header */
		if     ( i == 1  )  setMAC( *(fETHDR.ether_dhost), dETHDR.ether_dhost, buf );
		else if( i == 2  )  setMAC( *(fETHDR.ether_shost), dETHDR.ether_shost, buf );
		else if( i == 3  )  dETHDR.ether_type = setFlag16_t( false, fETHDR.ether_type, buf );

		/* IP Header */
		else if( i == 4  )  dIPHDR.ip_v   = setNum4_t( true, (uint8_t *)fIPHDR, buf ) & 0xf;
		else if( i == 5  )  dIPHDR.ip_hl  = setNum4_t( false, (uint8_t *)fIPHDR, buf ) & 0xf;
		else if( i == 6  )  dIPHDR.ip_tos = setFlag8_t( true, fIPHDR.ip_tos, buf );
		else if( i == 7  )  dIPHDR.ip_len = setNum16_t( fIPHDR.ip_len, buf );
		else if( i == 8  )  dIPHDR.ip_id  = setHex16_t( fIPHDR.ip_id, buf );
		else if( i == 9  )  dIPHDR.ip_off = setFlag16_t( true, fIPHDR.ip_off, buf );
		else if( i == 10 )  dIPHDR.ip_ttl = setNum8_t( fIPHDR.ip_ttl, buf );
		else if( i == 11 )  dIPHDR.ip_p   = setFlag8_t( false, fIPHDR.ip_p, buf );
		else if( i == 12 )  dIPHDR.ip_sum = setHex16_t( fIPHDR.ip_sum, buf );
		else if( i == 13 )  setIP( fIPHDR.ip_src, &dIPHDR.ip_src, buf );

		else if( i == 14 ) {
			setIP( fIPHDR.ip_dst, &dIPHDR.ip_dst, buf );

			if( dIPHDR.ip_p == IPPROTO_IP ) {
				for(; i < num; i++)
					fgets(buf, MAXPAYLOAD, fp);

			}else if( dIPHDR.ip_p == IPPROTO_UDP ) {
				for(; i < 27; i++)
					fgets(buf, MAXPAYLOAD, fp);

				i = 24;  // go to UDP
			}
		}/* TCP Header */
		else if( i == 15 )  dTCPHDR.source  = setPORT( fTCPHDR.source, buf );
		else if( i == 16 )  dTCPHDR.dest    = setPORT( fTCPHDR.dest, buf );
		else if( i == 17 )  dTCPHDR.seq     = htonl(setNum32_t( fTCPHDR.seq, buf ));
		else if( i == 18 )  dTCPHDR.ack_seq = htonl(setNum32_t( fTCPHDR.ack_seq, buf ));
		else if( i == 19 )  dTCPHDR.doff    = setNum4_t( true,  (uint8_t *)fTCPHDR + 12, buf ) & 0xf;
		else if( i == 22 )  dTCPHDR.window  = setNum16_t( fTCPHDR.window, buf );
		else if( i == 23 )  dTCPHDR.check   = setHex16_t( fTCPHDR.check, buf );
		else if( i == 21 )  setFlags( fTCPHDR, &dTCPHDR, buf ); // Flags

		else if( i == 24 ) {
			dTCPHDR.urg_ptr = setNum16_t( fTCPHDR.urg_ptr, buf );
			if( dIPHDR.ip_p == IPPROTO_TCP ) {
				if( !http )
					break;
				else {
					for(; i < 28; i++)
						fgets(buf, MAXPAYLOAD, fp);
				}
			}
		}else if( i == 20 ) { // Reserved
			if( buf[0] != '0' )
				printf("Format Error: %s\n",buf);

		}/* UDP Header */
		else if( i == 25 )  dUDPHDR.source = setPORT( fUDPHDR.source, buf );
		else if( i == 26 )  dUDPHDR.dest   = setPORT( fUDPHDR.dest, buf );
		else if( i == 27 )  dUDPHDR.len    = setNum16_t( fUDPHDR.len, buf );
		else if( i == 28 )  dUDPHDR.check  = setHex16_t( fUDPHDR.check, buf );

		/* HTTP Request */
		else if( i == 29 ) {
			if( http ) {
				strncpy( node->http, buf, strlen(buf) );
				node->http[4] = '\0';
			}
		}
	}

	/* Payload */
	while( fgets(buf, MAXPAYLOAD, fp) != NULL ) {
		if( strncmp(buf, "/* Payload */", 13) == 0 )
			break;
	}

	if( fgets(buf, MAXPAYLOAD, fp) != NULL ) {
		if( buf[0] != '\n' ) {
			memcpy(node->payload, buf, strlen(buf) - 1);
			return;
		}
	}
}

static bool setMAC(uint8_t * const flag, uint8_t *host, const char * const buf)
{
	uint8_t div = 0, i = 0;
	uint16_t tmp = 0;

	while( buf[i] != '\0' ) {
		if( isNUM(buf[i]) ) {
			tmp *= 16;
			tmp += buf[i++] - 48;

		}else if( isUPPER(buf[i]) ) {
			tmp *= 16;
			tmp += buf[i++] - 55;

		}else if( isLOWER(buf[i]) ) {
			tmp *= 16;
			tmp += buf[i++] - 87;

		}else if( buf[i] == ':' ) {
			if( tmp > 255 || div > 6)
				return errform(buf);

			host[div++] = (uint8_t)tmp;
			tmp = 0;
			i++;

		}else	return errform(buf);
	}

	// last field
	if( tmp > 255 || div != 5 )
		return errform(buf);

	host[div] = (uint8_t)tmp;
	memset(flag, 0xff, 6);
	return true;
}

static bool setIP(struct in_addr * const flag, struct in_addr *ip, const char * const buf)
{
	if( inet_aton(buf, ip) == 0 )
		return errform(buf);
	
	memset(flag, 0xff, sizeof(struct in_addr));
	
	return true;
}

static uint16_t setPORT(uint16_t * const flag, const char * const buf)
{
	uint32_t port = 0;
	uint8_t i = 0;

	while( buf[i] != '\0' ) {
		if( isNUM(buf[i]) ) {
			port *= 10;
			port += buf[i++] - 48;

		}else	return errform(buf);
	}

	memset(flag, 0xff, 2);
	return htons(port);
}

static uint8_t setFlag8_t(bool loop, uint8_t * const flag, const char * const buf)
{
	uint8_t sum = 0, i = 0;

	memset(flag, 0xff, 1);

	if( loop == true ) {
	// Precedence & ToS
		while( buf[i] != '\0' ) {
			if( buf[i] == ' ' ) {
				i++;
				continue;
			}
			if( strncmp(buf, "Routine", 7) == 0 ) {
				sum |= 0x00;
				i += 7;
			// Not for HW
			}else if( strncmp(buf, "Priority", 8) == 0 ) {
				sum |= 0x01;
				i += 8;
			}else if( strncmp(buf, "Immediate", 9) == 0 ) {
				sum |= 0x02;
				i += 9;
			}else if( strncmp(buf, "Flash", 5) == 0 ) {
				sum |= 0x03;
				i += 5;
			}else if( strncmp(buf, "Override", 8) == 0 ) {
				sum |= 0x04;
				i += 8;
			}else if( strncmp(buf, "Critical", 8) == 0 ) {
				sum |= 0x05;
				i += 8;
			}else if( strncmp(buf, "Internetwork", 12) == 0 ) {
				sum |= 0x06;
				i += 12;
			}else if( strncmp(buf, "Network", 7) == 0 ) {
				sum |= 0x07;
				i += 7;
			}else if( strncmp(buf, "Minimum Delay", 13) == 0 ) {
				sum |= 0x08;
				i += 13;
			}else if( strncmp(buf, "Maximum Throughput", 18) == 0 ) {
				sum |= 0x10;
				i += 18;
			}else if( strncmp(buf, "Maximum Reliability", 19) == 0 ) {
				sum |= 0x20;
				i += 19;
			}else if( strncmp(buf, "Minimum Cost", 12) == 0 ) {
				sum |= 0x40;
				i += 12;
			}else {
				memset(flag, 0, 1);
				return errform(buf);
			}
		}

		return sum;
	}else {
	// Pprotocol
		if     ( strncmp(buf, "TCP ", 3) == 0 )  return 6;
		else if( strncmp(buf, "UDP" , 3) == 0 )  return 17;
		else if( strncmp(buf, "HTTP", 4) == 0 )  {
			http = true;
			return 6;
		}
		// Not for HW
		else if( strncmp(buf, "IP"      , 2) == 0 )  return 0;
		else if( strncmp(buf, "Hop"     , 3) == 0 )  return 0;
		else if( strncmp(buf, "ICMP"    , 4) == 0 )  return 1;
		else if( strncmp(buf, "IGMP"    , 4) == 0 )  return 2;
		else if( strncmp(buf, "IPIP"    , 4) == 0 )  return 4;
		else if( strncmp(buf, "EGP"     , 3) == 0 )  return 8;
		else if( strncmp(buf, "PUP"     , 3) == 0 )  return 12;
		else if( strncmp(buf, "IDP"     , 3) == 0 )  return 22;
		else if( strncmp(buf, "TPC4"    , 4) == 0 )  return 29;
		else if( strncmp(buf, "DCCP"    , 4) == 0 )  return 33;
		else if( strncmp(buf, "IPv6"    , 4) == 0 )  return 41;
		else if( strncmp(buf, "Route"   , 5) == 0 )  return 43;
		else if( strncmp(buf, "Fragment", 8) == 0 )  return 44;
		else if( strncmp(buf, "RSVP"    , 4) == 0 )  return 46;
		else if( strncmp(buf, "GRE"     , 3) == 0 )  return 47;
		else if( strncmp(buf, "ESP"     , 3) == 0 )  return 50;
		else if( strncmp(buf, "AH"      , 2) == 0 )  return 51;
		else if( strncmp(buf, "ICMPv6"  , 6) == 0 )  return 58;
		else if( strncmp(buf, "None"    , 4) == 0 )  return 59;
		else if( strncmp(buf, "DSTOPTS" , 7) == 0 )  return 60;
		else if( strncmp(buf, "MTP"     , 3) == 0 )  return 92;
		else if( strncmp(buf, "Encap"   , 5) == 0 )  return 98;
		else if( strncmp(buf, "PIM"     , 3) == 0 )  return 103;
		else if( strncmp(buf, "COMP"    , 4) == 0 )  return 108;
		else if( strncmp(buf, "SCTP"    , 4) == 0 )  return 132;
		else if( strncmp(buf, "UDP-Lite", 8) == 0 )  return 136;
		else if( strncmp(buf, "Raw"     , 3) == 0 )  return 255;
	}

	memset(flag, 0, 1);
	return errform(buf);
}

static uint16_t setFlag16_t(bool loop, uint16_t * const flag, const char * const buf)
{
	int len = strlen(buf);
	uint32_t tmp; 
	uint16_t sum = 0;
	uint8_t i = 0;

	if( loop == true ) {
	// Fragment
		while( i < len ) {
			if( buf[i] == ' ' ) {
				i++; 
			}else if( strncmp(buf, "DF", 2) == 0 ) {
				*flag |= 64;
				sum |= 0x4000;
				i += 2;
			}else if( strncmp(buf, "MF", 2) == 0 ) {
				*flag |= 32;
				sum |= 0x2000;
				i += 2;
			}else {
				tmp = 0;
				while( buf[i] != '\0' && buf[i] != ' ' ) {
					if( !isNUM(buf[i]) )
						return errform(buf);

					tmp *= 10;
					tmp += buf[i++] - 48;
				}

				if( tmp > 65535 )
					return overflow(buf);

				*flag |= 65311;
				sum |= (uint16_t)tmp;
			}
		}

		return htons(sum);
	}else {
	// Type (Little Endian)
		memset(flag, 0xff, 2);

		if     ( strncmp(buf, "Xerox PUP"     , 9 ) == 0 )  return 0x0002;
		else if( strncmp(buf, "Sprite"        , 6 ) == 0 )  return 0x0005;
		else if( strncmp(buf, "IP"            , 2 ) == 0 )  return 0x0008;
		else if( strncmp(buf, "ARP"           , 3 ) == 0 )  return 0x0608;
		else if( strncmp(buf, "Reverse ARP"   , 11) == 0 )  return 0x3580;
		else if( strncmp(buf, "Apple Talk"    , 10) == 0 )  return 0x9B80;
		else if( strncmp(buf, "Apple Talk ARP", 14) == 0 )  return 0xF380;
		else if( strncmp(buf, "VLAN"          , 4 ) == 0 )  return 0x0081;
		else if( strncmp(buf, "IPX"           , 3 ) == 0 )  return 0x3781;
		else if( strncmp(buf, "IPv6"          , 4 ) == 0 )  return 0xDD86;
		else if( strncmp(buf, "Loop back"     , 9 ) == 0 )  return 0x0090;
	}

	memset(flag, 0, 2);
	return errform(buf);
}

static bool setFlags(struct tcphdr * const flag, struct tcphdr *data, const char * const buf)
{
	uint8_t i = 0;
	while( buf[i] != '\0' ) {
		if( buf[i] == ' ' ) {
			i++;

		}else if( strncmp(buf + i, "URG", 3) == 0 ) {
			flag->urg = 1;
			data->urg = 1;
			i += 3;

		}else if( strncmp(buf + i, "ACK", 3) == 0 ) {
			flag->ack = 1;
			data->ack = 1;
			i += 3;

		}else if( strncmp(buf + i, "PSH", 3) == 0 ) {
			flag->psh = 1;
			data->psh = 1;
			i += 3;

		}else if( strncmp(buf + i, "RST", 3) == 0 ) {
			flag->rst = 1;
			data->rst = 1;
			i += 3;

		}else if( strncmp(buf + i, "SYN", 3) == 0 ) {
			flag->syn = 1;
			data->syn = 1;
			i += 3;

		}else if( strncmp(buf + i, "FIN", 3) == 0 ) {
			flag->fin = 1;
			data->fin = 1;
			i += 3;
		// Not for HW
		}else if( strncmp(buf + i, "NS", 2) == 0 ) {
			flag->res1 |= 8;
			data->res1 |= 8;
			i += 2;
		}else if( strncmp(buf + i, "CWR", 3) == 0 ) {
			flag->res2 |= 1;
			data->res2 |= 1;
			i += 3;
		}else if( strncmp(buf + i, "ECE", 3) == 0 ) {
			flag->res2 |= 2;
			data->res2 |= 2;
			i += 3;
		
		}else   return errform(buf);
	}

	return true;
}


static uint8_t setNum8_t(uint8_t * const flag, const char * const buf)
{
	uint16_t num = 0;
	uint8_t i = 0;

	while( buf[i] != '\0' ) {
		if( buf[i] < '0' || buf[i] > '9' )
			return errform(buf);

		num *= 10;
		num += buf[i++] - 48;

		if( num > 255 )
			return overflow(buf);
	}

	memset(flag, 0xff, 1);
	return (uint8_t)num;
}

static uint16_t setNum16_t(uint16_t * const flag, const char * const buf)
{
	uint32_t num = 0;
	uint8_t i = 0;

	while( buf[i] != '\0' ) {
		if( !isNUM(buf[i]) )
			return errform(buf);

		num *= 10;
		num += buf[i++] - 48;

		if( num > 65535 )
			return overflow(buf);
	}

	memset(flag, 0xff, 2);
	return htons((uint16_t)num);
}

static uint32_t setNum32_t(uint32_t * const flag, const char * const buf)
{
	long unsigned int num = 0;
	uint8_t i = 0;

	while( buf[i] != '\0' ) {
		if( !isNUM(buf[i]) )
			return errform(buf);

		num *= 10;
		num += buf[i++] - 48;

		if( num > 4294967295 )
			return overflow(buf);
	}

	memset(flag, 0xff, 4);
	return htonl((uint32_t)num);
}

static uint8_t setNum4_t(bool push, uint8_t * const flag, const char * const buf)
{
	uint8_t num = 0;
	uint8_t i = 0;

	while( buf[i] != '\0' ) {
		if( !isNUM(buf[i]) )
			return errform(buf);

		num *= 10;
		num += buf[i++] - 48;

		if( num > 15 )
			return overflow(buf);
	}

	*flag |= (push == true) ? 0xf0 : 0x0f;

	return num;
}

static uint16_t setHex16_t(uint16_t * const flag, const char * const buf)
{
	uint32_t num = 0;
	uint8_t i = 0;

	while( buf[i] != '\0' ) {
		if( isNUM(buf[i]) ) {
			num *= 16;
			num += buf[i++] - 48;

		}else if( isUPPER(buf[i]) ) {
			num *= 16;
			num += buf[i++] - 55;

		}else if( isLOWER(buf[i]) ) {
			num *= 16;
			num += buf[i++] - 87;

		}else	return errform(buf);

		if( num > 65535 )
			return overflow(buf);
	}

	memset(flag, 0xff, 2);
	return htons((uint16_t)num);
}
