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

#endif	/* !TWS_UTIL_H */
