/*
 * Copyright (c) 2010 River Tarnell.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef TWS_UTIL_H
#define TWS_UTIL_H

	void outofmemory(void);
	char *xstrdup(const char *);
	void *xmalloc(size_t);
	void *xcalloc(size_t, size_t);

	char *htmlescape(const char *str);

	int fd_set_nonblocking(int);
	int fd_set_cloexec(int);

	guint hdr_hash(gconstpointer key);
	gboolean hdr_equal(gconstpointer a, gconstpointer b);

#endif	/* !TWS_UTIL_H */
