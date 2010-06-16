/*
 * Copyright (c) 2010 River Tarnell.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef TWS_CGI_H
#define TWS_CGI_H

#include	"file.h"
#include	"net.h"

	/* Take over a request and handle it as a CGI */
	void handle_cgi_request(client_t *, file_request_t *);

#endif	/* !TWS_CGI_H */
