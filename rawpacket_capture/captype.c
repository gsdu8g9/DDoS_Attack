#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "captype.h"

struct linkedlist *alloc_node(const char * const filename)
{
	size_t len = sizeof(struct linkedlist);
	struct linkedlist *new = malloc(len);
	if( new == NULL ) {
		perror("malloc(): ");
		return NULL;
	}else {
		memset(new, 0, len);

		if( filename != NULL )
			memcpy(new->file, filename, strlen(filename));

		return new;
	}
}
