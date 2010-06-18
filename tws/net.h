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
#include	<zlib.h>
#include	<openssl/ssl.h>

#include	"config.h"

#if defined(__FreeBSD__)
# define USE_SENDFILE
#endif

#define READ_BUFSZ	1024

extern char *server_version;
extern char current_time[];

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

#define HTTP_CONTINUE			100
#define	HTTP_SWITCHING_PROTOCOLS	101
#define HTTP_OK				200
#define HTTP_CREATED			201
#define HTTP_ACCEPTED			202
#define HTTP_NOTAUTH			203
#define HTTP_NOCONTENT			204
#define HTTP_RESET_CONTENT		205
#define HTTP_PARTIAL_CONTENT		206
#define HTTP_MULTIPLE_CHOICES		300
#define HTTP_MOVED_PERMANENTLY		301
#define HTTP_FOUND			302
#define HTTP_SEE_OTHER			303
#define HTTP_NOT_MODIFIED		304
#define HTTP_USE_PROXY			305
#define HTTP_TEMPORARY_REDIRECT		307
#define HTTP_BAD_REQUEST		400
#define HTTP_UNAUTHORIZED		401
#define HTTP_FORBIDDEN			403
#define HTTP_NOT_FOUND			404
#define HTTP_NOT_ALLOWED		405
#define HTTP_NOT_ACCEPTABLE		406
#define HTTP_REQUEST_TIMEOUT		408
#define HTTP_CONFLICT			409
#define HTTP_GONE			410
#define HTTP_LENGTH_REQUIRED		411
#define HTTP_PRECONDITION_FAILED	412
#define HTTP_REQUEST_TOO_LARGE		413
#define HTTP_REQUEST_URI_TOO_LONG	414
#define HTTP_RANGE_NOT_SATISFIABLE	416
#define HTTP_EXPECTATION_FAILED		417
#define HTTP_INTERNAL_SERVER_ERROR	500
#define HTTP_NOT_IMPLEMENTED		501
#define HTTP_BAD_GATEWAY		502
#define HTTP_SERVICE_UNAVAILABLE	503
#define HTTP_GATEWAY_TIMEOUT		504
#define HTTP_VERSION_NOT_SUPPORTED	505
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

typedef enum {
	CGI_READ_HEADERS,
	CGI_READ_BODY
} cgi_state_t;

typedef enum {
	COMP_NONE = 0,
	COMP_GZIP,
	COMP_DEFLATE
} compr_type_t;

typedef struct {
	GHashTable		*headers;
	char			*method_str;
	char			*url;
	char			*query;
	http_version_t		 version;
	http_method_t		 method;
	vhost_t			*vhost;

	struct {
		int		 keepalive:1;		/* Client wants keep-alive	*/
		int		 userdir:1;		/* Request is ~user		*/
		int		 accept_chunked:1;	/* Client supports chunked TE	*/
		int		 write_chunked:1;	/* Chunked TE in effect		*/
	} flags;

	compr_type_t		 compress;
	compr_type_t		 can_compress;
	z_stream		*zstream;

	/* Response headers */
	GHashTable		*resp_headers;
	char			*resp_status;

	/* Common to file and CGI requests */
	char	*filename;
	char	*urlname; /* Common part of URL and filename */
	char	*username;
	char	*pathinfo;
	char	*mimetype;

	/* For file requests */
	int	 fd;
	off_t	 bytesdone;
	off_t	 bytesleft;

	/* For CGI requests */
	pid_t		 pid;
	int		 fd_write;
	int		 fd_read;
	struct event	 ev;
	cgi_state_t	 cgi_state;

	/* CGI headers read from the script */
	GHashTable	*cgi_headers;
	struct evbuffer	*cgi_buffer;
	
	/* For CGI PUT/POST */
	off_t		 post_length;
	struct evbuffer	*cgi_write_buffer;
} request_t;

	request_t	*request_new(void);
	void		 free_request(request_t *);

struct client;

	typedef void (*client_drain_callback) (struct client *, int err);

typedef struct client {
	struct sockaddr_storage	 addr;
	socklen_t		 addrlen;
	char			 ip[NI_MAXHOST];
	char			 hostname[NI_MAXHOST];

	struct event		 ev;
	struct evbuffer		*buffer;
	struct evbuffer		*wrbuf;
	int			 fd;

	SSL			*ssl;
	struct event		 ssl_ev;
	void (*ssl_read_cb)	(int, short, void *);
	void (*ssl_write_cb)	(int, short, void *);
	char			 sslbuf[1024];
	int			 sslbufsz;

	client_state_t		 state;
	request_t		*request;

	/* Private to handler */
	void			*hdldata;
	/* For client_drain */
	client_drain_callback	 drain_cb;
} client_t;

	void client_close(client_t *);
	void client_abort(client_t *);
	void client_write(client_t *, const char *buf, size_t sz);
	void client_printf(client_t *, const char *fmt, ...);
	void client_drain(client_t *, client_drain_callback);
	void client_send_error(client_t *, int);
	void client_start_response(client_t *, client_drain_callback);
	void client_add_header(client_t *, const char *, const char *);
	void client_redirect(client_t *, const char *, int);

	void client_error(client_t *, const char *fmt, ...);
	void client_warn(client_t *, const char *fmt, ...);
	void client_notice(client_t *, const char *fmt, ...);

	void net_init(void);
	int net_listen(void);
	void net_run(void);

#endif	/* !TWS_NET_H */
