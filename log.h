/*
 * Copyright (c) 2010 River Tarnell.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef TWS_LOG_H
#define TWS_LOG_H

#include	<stdarg.h>

typedef enum {
	TLOG_NOTICE = 0,
	TLOG_WARN,
	TLOG_ERROR
} tws_log_type_t;

	int log_open(void);
	void log_close(void);

	void vlog(tws_log_type_t, const char *fmt, va_list);
	void tlog(tws_log_type_t, const char *fmt, ...);
	void log_notice(const char *fmt, ...);
	void log_warn(const char *fmt, ...);
	void log_error(const char *fmt, ...);

#endif	/* !TWS_LOG_H */
