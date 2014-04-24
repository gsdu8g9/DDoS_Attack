#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "filter.h"

static void current_file(const struct linkedlist *node);
static bool add_file(struct linkedlist *node, char file[]);
static bool delete_file(struct linkedlist *node, const int num);
static int update_file(struct linkedlist *node, const int num);
static void deleteall(struct linkedlist *node);

static void logging(const struct linkedlist *node);
//static void printall(struct linkedlist *node);

void menu(struct linkedlist *node, const pid_t pid)
{
	char file[MAXFILENAME];
	int ch;

	while( true ) {
		current_file(node);
		printf("[1] Add_file   [2] Delete_file   [3] Update_file   [4] Scanning   [5] Finish\n>> ");

		do {
			ch = getchar();
		}while( ch < '1' || ch > '6' );
		getchar(); // Accept '\n'

		switch( ch ) {
			case '1':
				printf("Enter filename to add: ");
				if( fgets( file, MAXFILENAME, stdin ) == NULL ) {
					printf("fgets(): Failure\n");
					exit(EXIT_FAILURE);

				}else if( add_file( node, file ) == false )
					printf("Addfile(): Failure\n");
				else
					system("clear");
				break;

			case '2':
				printf("Select filenumber to delete: ");
				if( (ch = delete_file( node, getchar() - '0' )) == false )
					printf("Deletefile(): No such a file\n");
				else
					system("clear");
				break;

			case '3':
				printf("Select filenumber to update: ");
				if( (ch = update_file( node, getchar() - '0' )) == -1 )
					printf("Editfile(): No such a file\n");

				else if( ch == 0 )
					printf("Editfile(): Failure\n");
				else
					system("clear");
				break;

			case '4':
				if( kill(pid, SIGTERM) == -1 ) {
					perror("kill(): ");
					exit(EXIT_FAILURE);
				}else {
					system("clear");
					logging(node);
					return;
				}

			case '5':
				if( kill(pid, SIGTERM) == -1 ) {
					perror("kill(): ");
					exit(EXIT_FAILURE);
				}else {
					deleteall(node->next);
					printf("Bye :)\n");
					exit(EXIT_SUCCESS);
				}
		}
	}
}

static void current_file(const struct linkedlist *node)
{
	int i = 1;

	printf("\n======== Current Fields ========\n");
	while( node->next != NULL ) {
		node = node->next;
		printf("[%d] %s\n", i++, node->file);
	}
	printf("================================\n\n");
}

static bool add_file(struct linkedlist *node, char filename[])
{
	int len = strlen(filename);

	if( filename[len-1] == '\n' )
		filename[len-1] = '\0';

	FILE *fp = fopen(filename, "r");
	if( fp == NULL ) {
		perror("fopen(): ");
		return false;
	}

	while( node->next != NULL )
		node = node->next;
	
	if( (node->next = alloc_node(filename)) == NULL )
		return false;

	parse(fp, node->next);

	return true;
}

static bool delete_file(struct linkedlist *node, int num)
{
	struct linkedlist *tmp;
	int i = 0;

	while( node->next != NULL ) {
		if( ++i == num ) {
			tmp = node->next->next;
			free(node->next);
			node->next = tmp;

			return true;
		}else
			node = node->next;
	}
	return false;
}

static int update_file(struct linkedlist *node, int num)
{
	struct linkedlist *tmp = node;
	FILE *fp;
	int i = 0;

	if( num < 1 )
		return false;
	
	// point node to be updated
	while( node->next != NULL ) {
		node = node->next;

		if( ++i == num ) break;
	}

	if( i-- != num )  // invalid 
		return -1;

	// point previous node to be updated
	while( i-- )
		tmp = tmp->next;

	if( (tmp->next = alloc_node(node->file)) == NULL )
		return false;
	else {
		fp = fopen(node->file, "r");
		if( fp == NULL ) {
			perror("fopen(): ");
			free(tmp->next);
			tmp->next = node;

			return false;
		}
	}

	parse(fp, tmp->next);
	tmp->next->next = node->next;
	free(node);

	return true;
}

static void deleteall(struct linkedlist *node)
{
	if( node == NULL)
		return;

	if( node->next != NULL )
		deleteall(node->next);
	else
		free(node);
}

static void logging(const struct linkedlist *node)
{
	FILE *fp = fopen("Filter.log", "a");
	char *t = (char *)gettime();
	fprintf(fp, "%s ----- Restart\n", t);

	int i = 1;

	while( node->next != NULL ) {
		node = node->next;
		fprintf(fp, "  * [%d] %s\n", i++, node->file);
	}
	
	fclose(fp);
	free(t);
}

char* gettime()
{
	time_t cur = time(NULL);
	struct tm *d = localtime(&cur);

	char *t = (char *)malloc(15);
	if( t == NULL )
		perror("malloc(): ");
	strncpy(t, asctime(d) + 4, 15);
	return t;
}
/*
static void printall(struct linkedlist *node)
{
	while( node->next != NULL ) {
		node = node->next;
		int len;
		if( node->data.iphdr.ip_p == 6 ) {
			len = sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr);
		}else {
			len = sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr);
		}

		rawprint((uint8_t *)&node->flag + 2, len);
		rawprint((uint8_t *)&node->data + 2, len);
		if( strlen(node->payload) > 0 )
			rawprint((uint8_t *)node->payload, strlen(node->payload));
	}
}

void rawprint(const uint8_t * const packet, int packetlen)
{
	printf("------- RAW -------\n");
	int i = 0;
	while( i < packetlen ) {
		printf("%02x ", *(packet+i));
		if( ++i%16 == 0 ) printf("\n");
	}
	if( i%16 != 0 ) printf("\n-------------------\n");
	else printf("-------------------\n");
}
*/
