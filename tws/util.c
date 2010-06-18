/*
 * Copyright (c) 2010 River Tarnell.  All rights reserved.
 * Use is subject to license terms.
 */

#include	<stdlib.h>
#include	<string.h>
#include	<unistd.h>
#include	<fcntl.h>

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

char *
htmlescape(const char *str)
{
char	*res = xmalloc(strlen(str) * 7 + 1);
char	*s = res;

	*s = 0;

	while (*str) {
		switch (*str) {
		case '<':
			strcat(s, "&lt;");
			s += 4;
			break;
		case '>':
			strcat(s, "&gt;");
			s += 4;
			break;
		case '&':
			strcat(s, "&amp;");
			s += 5;
			break;
		case '"':
			strcat(s, "&dquot;");
			s += 7;
			break;
		case '\'':
			strcat(s, "&quot;");
			s += 6;
			break;
		default:
			*s++ = *str;
			break;
		}

		str++;
	}

	*s = 0;
	return res;
}

int
fd_set_nonblocking(int fd)
{
int	fl;
	if ((fl = fcntl(fd, F_GETFL, 0)) == -1)
		return -1;
	fl |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, fl) == -1)
		return -1;
	return 0;
}

int
fd_set_cloexec(int fd)
{
int	fl;
	if ((fl = fcntl(fd, F_GETFL, 0)) == -1)
		return -1;
	fl |= FD_CLOEXEC;
	if (fcntl(fd, F_SETFL, fl) == -1)
		return -1;
	return 0;
}

