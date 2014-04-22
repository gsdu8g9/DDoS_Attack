#include <stdio.h>
#include <stdlib.h>
#include <openssl/md5.h>

char *md5_hash(char *str, int len)
{
	int n;
	char *hash = malloc(16);
	if( hash == NULL ) {
		perror("malloc(): ");
		return NULL;
	}

	MD5(str, len, hash);

	return hash;
}
