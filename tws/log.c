/*
 * Copyright (c) 2010 River Tarnell.  All rights reserved.
 * Use is subject to license terms.
 */

#include	<stdio.h>
#include	<time.h>
#include	<string.h>
#include	<stdarg.h>

#include	"log.h"

FILE	*logfile;

int
log_open()
{
	logfile = stdout;
	return 0;
}

void
log_close()
{
}

void
vlog(type, fmt, ap)
	tws_log_type_t	 type;
	const char	*fmt;
	va_list		 ap;
{
char		 tbuf[128];
time_t		 now;
struct tm	*tm;
static const char *const types[] = {
	"NOTICE", "WARNING", "ERROR"
};

	(void) time(&now);
	tm = localtime(&now);
	(void) strftime(tbuf, sizeof (tbuf), "%Y-%m-%d %H:%M:%S", tm);
	(void) fprintf(logfile, "[%s] %s: ", tbuf, types[type]);
	(void) vfprintf(logfile, fmt, ap);
	(void) fputc('\n', logfile);
	}

void
tlog(tws_log_type_t type, const char *fmt, ...)
{
va_list	ap;
	va_start(ap, fmt);
	vlog(type, fmt, ap);
	va_end(ap);
}

void
log_notice(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vlog(TLOG_NOTICE, fmt, ap);
	va_end(ap);
}

void
log_warn(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vlog(TLOG_WARN, fmt, ap);
	va_end(ap);
}

void
log_error(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vlog(TLOG_ERROR, fmt, ap);
	va_end(ap);
}
