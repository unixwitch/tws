/*
 * Copyright (c) 2010 River Tarnell.  All rights reserved.
 * Use is subject to license terms.
 */

#include	<stdlib.h>
#include	<string.h>
#include	<unistd.h>

#include	"util.h"
#include	"log.h"

void *
xmalloc(size_t sz)
{
void	*ret;
	if ((ret = malloc(sz)) == NULL)
		outofmemory();
	return ret;
}

void *
xcalloc(size_t n, size_t sz)
{
void	*ret;
	if ((ret = calloc(n, sz)) == NULL)
		outofmemory();
	return ret;
}

char *
xstrdup(const char *str)
{
void	*ret;
	if ((ret = strdup(str)) == NULL)
		outofmemory();
	return ret;
}

void
outofmemory()
{
	log_error("out of memory");
	_exit(1);
}
