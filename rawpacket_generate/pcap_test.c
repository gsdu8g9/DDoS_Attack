#include <sys/time.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0

extern char *inet_ntoa();

// IP 헤더 구조체
struct ip *iph;

// TCP 헤더 구조체
struct tcphdr *tcph;

// 패킷을 받아들일경우 이 함수를 호출한다.  
// packet 가 받아들인 패킷이다.
void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, 
		const u_char *packet)
{
/* ME */
	const u_char *tmp = packet;
	tmp+=23;
	if( *tmp != 0x00 && *tmp != 0x06 && *tmp != 0x11 ) {
		return;
	}

	unsigned int len = pkthdr->len;
	int nt = 0;
	fprintf(stdout, "packet:	");
	while(len--) {
		printf("%02x ", *(packet++));
		if( (++nt % 16) == 0 ) printf("\n\t");
	}
	fprintf(stdout, "\n");

	return;



/* YOU */
	static int count = 1;
	struct ether_header *ep;
	unsigned short ether_type;    
	int chcnt =0;
	int length=pkthdr->len;

	// 이더넷 헤더를 가져온다. 
	ep = (struct ether_header *)packet;

	// IP 헤더를 가져오기 위해서 
	// 이더넷 헤더 크기만큼 offset 한다.   
	packet += sizeof(struct ether_header);

	// 프로토콜 타입을 알아낸다. 
	ether_type = ntohs(ep->ether_type);

	// 만약 IP 패킷이라면 
	if (ether_type == ETHERTYPE_IP)
	{
		// IP 헤더에서 데이타 정보를 출력한다.  
		iph = (struct ip *)packet;
		//printf("Version     : %d\n", iph->ip_v);
		//printf("Header Len  : %d\n", iph->ip_hl);
		//printf("Ident       : %d\n", iph->ip_id);
		//printf("TTL         : %d\n", iph->ip_ttl); 
		printf("Src Address : %s\n", inet_ntoa(iph->ip_src));
		printf("Dst Address : %s\n", inet_ntoa(iph->ip_dst));

		// 만약 TCP 데이타 라면
		// TCP 정보를 출력한다. 
		if (iph->ip_p == IPPROTO_TCP)
		{
			tcph = (struct tcphdr *)(packet + iph->ip_hl * 4);
			printf("TCP\n");
	//		printf("Src Port : %d\n" , ntohs(tcph->source));
	//		printf("Dst Port : %d\n" , ntohs(tcph->dest));
		}
		else if (iph->ip_p == IPPROTO_UDP)
		{
			struct udphdr *udph;
			udph = (struct udphdr *)(packet + iph->ip_hl * 4);
			printf("UDP\n");
			printf("Src Port : %d\n" , ntohs(udph->source));
			printf("Dst Port : %d\n" , ntohs(udph->dest));
		}
		else if (iph->ip_p == IPPROTO_IP)
		{
			printf("IP\n");
		}

		// Packet 데이타 를 출력한다. 
		// IP 헤더 부터 출력한다.  
		while(length--)
		{
			printf("%02x", *(packet++)); 
			if ((++chcnt % 16) == 0) 
				printf("\n");
		}
	}
	// IP 패킷이 아니라면 
	else
	{
		printf("NONE IP 패킷: %04x\n", ether_type);
	}
	printf("\n\n");
}    

int main(int argc, char **argv)
{
	char *dev;
	char *net;
	char *mask;

	bpf_u_int32 netp;
	bpf_u_int32 maskp;
	char errbuf[PCAP_ERRBUF_SIZE];
	int ret;
	struct pcap_pkthdr hdr;
	struct in_addr net_addr, mask_addr;
	struct ether_header *eptr;
	const u_char *packet;

	struct bpf_program fp;     

	pcap_t *pcd;  // packet capture descriptor

	// 사용중인 디바이스 이름을 얻어온다. 
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL)
	{
		printf("%s\n", errbuf);
		exit(1);
	}
	printf("DEV : %s\n", dev);

	// 디바이스 이름에 대한 네트웍/마스크 정보를 얻어온다. 
	ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
	if (ret == -1)
	{
		printf("%s\n", errbuf);
		exit(1);
	}

	// 네트웍/마스트 정보를 점박이 3형제 스타일로 변경한다. 
	net_addr.s_addr = netp;
	net = inet_ntoa(net_addr);
	printf("NET : %s\n", net);

	mask_addr.s_addr = maskp;
	mask = inet_ntoa(mask_addr);
	printf("MSK : %s\n", mask);
	printf("=======================\n");

	// 디바이스 dev 에 대한 packet capture 
	// descriptor 를얻어온다.   
	pcd = pcap_open_live(dev, BUFSIZ,  PROMISCUOUS, -1, errbuf);
	if (pcd == NULL)
	{
		printf("%s\n", errbuf);
		exit(1);
	}    

	//if (pcap_compile(pcd, &fp, "tcp and src host 143.248.102.86 and not port 22", 0, netp) == -1)
	if (pcap_compile(pcd, &fp, "not port 22 and tcp", 0, netp) == -1)
	{
		perror("compile error: ");    
		exit(1);
	}
	if (pcap_setfilter(pcd, &fp) == -1)
	{
		perror("setfilter error\n");
		exit(0);    
	}
	// 지정된 횟수만큼 패킷캡쳐를 한다. 
	// pcap_setfilter 을 통과한 패킷이 들어올경우 
	// callback 함수를 호출하도록 한다. 
	pcap_loop(pcd, atoi(argv[1]), callback, NULL);
}

