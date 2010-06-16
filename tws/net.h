/*
 * Copyright (c) 2010 River Tarnell.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef TWS_NET_H
#define TWS_NET_H

#include	<sys/socket.h>
#include	<netdb.h>

#include	<event.h>
#include	<glib.h>

#include	"config.h"

#if defined(__FreeBSD__)
# define USE_SENDFILE
#endif

#define READ_BUFSZ	1024

/*
 * Event priorities.  We prioritise writing to clients first, followed
 * by reading existing clients, following by accepting new clients.  The
 * idea is to prevent new clients starving existing clients, and instead
 * getting rid of existing clients before accepting new ones.
 */
#define NPRIOS		10
#define ACCEPT_PRIO	9
#define READ_PRIO	6
#define WRITE_PRIO	3

typedef enum {
	READ_REQUEST,
	READ_HEADERS,
	HANDLE_REQUEST
} client_state_t;

typedef enum {
	HTTP_10,
	HTTP_11
} http_version_t;

/*
 * These are request types that we have special handling for.
 */
typedef enum {
	M_UNKNOWN,
	M_GET,
	M_PUT,
	M_POST,
	M_HEAD,
} http_method_t;

typedef struct {
	GHashTable		*headers;
	char			*method_str;
	char			*url;
	char			*query;
	http_version_t		 version;
	http_method_t		 method;
	vhost_t			*vhost;
	int			 keepalive;

	/* Common to file and CGI requests */
	char	*filename;
	char	*urlname; /* Common part of URL and filename */
	char	*username;
	char	*pathinfo;
	char	*mimetype;
	int	 userdir;

	/* For file requests */
	int	 fd;
	off_t	 bytesdone;
	off_t	 bytesleft;

	/* For CGI requests */
	pid_t		 pid;
	int		 fds[2];
	struct event	 ev;
} request_t;

	request_t	*request_new(void);
	void		 free_request(request_t *);

struct client;

	typedef void (*client_drain_callback) (struct client *, int err);

typedef struct client {
	struct sockaddr_storage	 addr;
	socklen_t		 addrlen;
	char			 ip[NI_MAXHOST];

	struct event		 ev;
	struct evbuffer		*buffer;
	struct evbuffer		*wrbuf;
	int			 fd;

	client_state_t		 state;
	request_t		*request;

	/* Private to handler */
	void			*hdldata;
	/* For client_drain */
	client_drain_callback	 drain_cb;
} client_t;

	void client_close(client_t *);
	void client_abort(client_t *);
	void client_drain(client_t *, client_drain_callback);
	void client_send_error(client_t *, int);

	void client_error(client_t *, const char *fmt, ...);
	void client_warn(client_t *, const char *fmt, ...);
	void client_notice(client_t *, const char *fmt, ...);

	int net_listen(void);
	void net_run(void);

#endif	/* !TWS_NET_H */
