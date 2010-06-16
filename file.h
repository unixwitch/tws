/*
 * Copyright (c) 2010 River Tarnell.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef TWS_FILE_H
#define TWS_FILE_H

#include	"net.h"
#include	"config.h"

typedef struct {
	char	*filename;
	char	*urlname; /* Common part of URL and filename */
	char	*username;
	char	*pathinfo;
	char	*query;
	char	*mimetype;
	int	 userdir;
	vhost_t	*vhost;

	/* For file requests */
	int	 fd;
	off_t	 bytesdone;
	off_t	 bytesleft;

	/* For CGI requests */
	pid_t		 pid;
	int		 fds[2];
	struct event	 ev;
} file_request_t;

	void handle_file_request(client_t *);

#endif	/* !TWS_FILE_H */
