/*
 * Copyright (c) 2010 River Tarnell.  All rights reserved.
 * Use is subject to license terms.
 */

#include	<sys/types.h>
#include	<sys/socket.h>
#include	<netinet/in.h>
#include	<netinet/tcp.h>
#include	<netdb.h>
#include	<string.h>
#include	<errno.h>
#include	<unistd.h>
#include	<stdlib.h>
#include	<fcntl.h>
#include	<assert.h>
#include	<stdio.h>
#include	<fnmatch.h>
#include	<signal.h>

#include	<glib.h>
#include	<event.h>
#include	<evdns.h>
#include	<zlib.h>
#include	<openssl/err.h>
#include	<openssl/ssl.h>

#include	"net.h"
#include	"config.h"
#include	"log.h"
#include	"file.h"
#include	"setup.h"
#include	"util.h"

char current_time[64] = "Thu, 1 Jan 1970 00:00:00 GMT";
char *server_version;

static struct timeval	 one_second = { 1, 0 };
static int		 nclients;
static struct event	 ev_time;
static GPtrArray	*listeners;
static struct event_base *default_base;

static void accept_client(int, short, void *);
static void client_start(client_t *);
static void client_lookup(client_t *);
static void client_dns(client_t *);
static void client_dns_reverse_done(int, char, int, int, void *, void *);
static void client_dns_forward_done(int, char, int, int, void *, void *);
static void client_read(int, short, void *);
static int client_read_request(client_t *);
static int client_read_header(client_t *);
static void client_last_chunk_done(client_t *, int);
static void error_done(client_t *, int);
static void exit_signal(int, short, void *);
static void update_time(int, short, void *);
static void suspend_listeners(void);
static void start_listeners(void);

typedef struct {
	int		 fd;
	struct event	 ev;
	SSL_CTX		*ssl_ctx;
} listener_t;

static int
do_one_listener(conf, addr)
	tws_listen_t	*conf;
	struct addrinfo	*addr;
{
char		 nbuf[NI_MAXHOST];
listener_t	*l = NULL;
int		 ret, fl;
int		 one = 1;

#ifdef SO_ACCEPTFILTER
struct accept_filter_arg afa;
#endif

	if ((l = calloc(1, sizeof (*l))) == NULL)
		goto err;
	l->fd = -1;

	ret = getnameinfo(addr->ai_addr, addr->ai_addrlen, 
			nbuf, sizeof (nbuf), NULL, 0, 
			NI_NUMERICHOST);
	if (ret != 0) {
		log_error("%s:%s: getnameinfo: %s\n", conf->addr, conf->port, gai_strerror(ret));
		goto err;
	}

	if (conf->ssl) {
		if ((l->ssl_ctx = SSL_CTX_new(SSLv23_server_method())) == NULL) {
			log_error("%s[%s]:%s: Cannot create SSL context: %s",
					conf->addr, nbuf, conf->port,
					ERR_error_string(ERR_get_error(), NULL));
			goto err;
		}

		if ((ret = SSL_CTX_use_certificate_file(l->ssl_ctx,
				conf->ssl_cert, SSL_FILETYPE_PEM)) != 1) {
			log_error("%s[%s]:%s: Cannot load SSL certificate: %s: %s",
					conf->addr, nbuf, conf->port, conf->ssl_cert,
					ERR_error_string(ERR_get_error(), NULL));
			goto err;
		}

		if ((ret = SSL_CTX_use_PrivateKey_file(l->ssl_ctx,
				conf->ssl_key, SSL_FILETYPE_PEM)) != 1) {
			log_error("%s[%s]:%s: Cannot load SSL private key: %s: %s",
					conf->addr, nbuf, conf->port, conf->ssl_key,
					ERR_error_string(ERR_get_error(), NULL));
			goto err;
		}

		if (conf->ssl_ciphers) {
			if (SSL_CTX_set_cipher_list(l->ssl_ctx, conf->ssl_ciphers) == 0) {
				log_error("%s[%s]:%s: No valid ciphers",
					conf->addr, nbuf, conf->port);
				goto err;
			}
		}

		SSL_CTX_set_options(l->ssl_ctx, SSL_OP_NO_SSLv2);
	}

	if ((l->fd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol)) == -1) {
		log_error("%s[%s]:%s: socket: %s", 
			conf->addr, nbuf, conf->port, strerror(errno));
		goto err;
	}

	if (setsockopt(l->fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == -1) {
		log_error("%s[%s]:%s: setsockopt(SO_REUSEADDR): %s", 
			conf->addr, nbuf, conf->port, strerror(errno));
		goto err;
	}

	if (bind(l->fd, addr->ai_addr, addr->ai_addrlen) == -1) {
		log_error("%s[%s]:%s: bind: %s", 
			conf->addr, nbuf, conf->port, strerror(errno));
		goto err;
	}

	if (listen(l->fd, conf->backlog) == -1) {
		log_error("%s[%s]:%s: listen: %s", 
			conf->addr, nbuf, conf->port, strerror(errno));
		goto err;
	}

		       
#ifdef SO_ACCEPTFILTER
	bzero(&afa, sizeof(afa));
	strcpy(afa.af_name, "httpready");
	if (setsockopt(l->fd, SOL_SOCKET, SO_ACCEPTFILTER, &afa, sizeof(afa)) == -1)
		log_warn("%s[%s]:%s: Enabling HTTP accept filter: %s", 
			conf->addr, nbuf, conf->port, strerror(errno));
#endif		

	event_set(&l->ev, l->fd, EV_READ, accept_client, l);
	event_priority_set(&l->ev, ACCEPT_PRIO);
	event_add(&l->ev, NULL);

	g_ptr_array_add(listeners, l);
	return 0;

err:
	if (l) {
		if (l->fd != -1)
			close(l->fd);
		free(l);
	}
	return -1;
}

static int
setup_listener(conf)
	tws_listen_t	*conf;
{
const char	*port = conf->port ? conf->port : "http";
struct addrinfo	 hints, *res = NULL, *r;
int		 ret;

	bzero(&hints, sizeof(hints));
	
	hints.ai_family = conf->protocol;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	ret = getaddrinfo(conf->addr, port, &hints, &res);
	if (ret != 0) {
		log_error("%s:%s: %s", conf->addr, port,
				gai_strerror(ret));
		goto err;
	}

	for (r = res; r; r = r->ai_next) {
		if (do_one_listener(conf, r) == -1)
			goto err;
	}

	return 0;

err:
	return -1;
}

int
net_listen()
{
guint	i;
static struct event ev_sigint;
static struct event ev_sigterm;
struct timeval timeout = { 1, 0 };

	SSL_load_error_strings();
	SSL_library_init();

	if ((default_base = event_init()) == NULL) {
		log_error("event_init: %s", strerror(errno));
		goto err;
	}

	log_notice("Using libevent %s [%s], %s, zlib %s, Glib %d.%d.%d",
			event_get_version(),
			event_get_method(),
			SSLeay_version(SSLEAY_VERSION),
			zlibVersion(),
			glib_major_version,
			glib_minor_version,
			glib_micro_version);

	if (evdns_init() == -1) {
		log_error("evdns_init: %s", strerror(errno));
		goto err;
	}

	if (event_priority_init(NPRIOS) == -1) {
		log_error("event_priority_set: %s", strerror(errno));
		goto err;
	}

	if ((listeners = g_ptr_array_new()) == NULL)
		goto err;

	for (i = 0; i < curconf->listeners->len; ++i) {
		if (setup_listener(g_ptr_array_index(curconf->listeners, i)) == -1)
			goto err;
	}

	event_set(&ev_sigint, SIGINT, EV_SIGNAL, exit_signal, NULL);
	event_set(&ev_sigterm, SIGINT, EV_SIGNAL, exit_signal, NULL);
	signal(SIGPIPE, SIG_IGN);
	event_add(&ev_sigint, NULL);
	event_add(&ev_sigterm, NULL);

	event_set(&ev_time, 0, EV_TIMEOUT | EV_PERSIST, update_time, NULL);
	update_time(0, 0, NULL);

	return 0;

err:
	if (listeners)
		g_ptr_array_free(listeners, TRUE);
	return -1;
}

void
net_run(void)
{
guint	i;

	for (i = 0; i < (curconf->nprocs - 1); ++i) {
		if (fork() == 0)
			break;
	}
	event_reinit(default_base);

	for (i = 0; i < listeners->len; i++) {
	int	fd = ((listener_t *) g_ptr_array_index(listeners, i))->fd;
		fd_set_cloexec(fd);
		fd_set_nonblocking(fd);
	}

	if (event_dispatch() == -1)
		log_error("event_dispatch: %s", strerror(errno));
}

static client_t *
client_new(
	int	fd
)
{
client_t	*client;

	client = xcalloc(1, sizeof(*client));
	client->fd = fd;

	if ((client->buffer = evbuffer_new()) == NULL)
		outofmemory();

	if ((client->wrbuf = evbuffer_new()) == NULL)
		outofmemory();

	return client;
}

request_t *
request_new()
{
request_t	*request;

	request = xcalloc(1, sizeof (*request));
	request->headers = g_hash_table_new_full(hdr_hash, hdr_equal, free, NULL);
	request->resp_headers = g_hash_table_new_full(hdr_hash, hdr_equal, free, free);
	request->cgi_write_buffer = evbuffer_new();

	return request;
}

void
accept_client(
	int	 fd,
	short	 ev,
	void	*arg
)
{
int		 cfd = -1, ret, one = 1;
listener_t	*l = arg;
client_t	 *client = NULL;

struct sockaddr_storage	addr;
socklen_t		addrlen = sizeof(addr);

	event_add(&l->ev, NULL);

	if ((cfd = accept(fd, (struct sockaddr *) &addr, &addrlen)) == -1) {
		if (errno != EAGAIN)
			log_error("accept: %s", strerror(errno));
		return;
	}

	if ((client = client_new(cfd)) == NULL) {
		log_error("accept_client: %s", strerror(errno));
		goto err;
	}

	if ((client->request = request_new()) == NULL) {
		log_error("accept_client: %s", strerror(errno));
		goto err;
	}

	fd_set_nonblocking(cfd);
	fd_set_cloexec(cfd);

	bcopy(&addr, &client->addr, sizeof(addr));
	client->addrlen = addrlen;
	client->state = READ_REQUEST;

	ret = getnameinfo((struct sockaddr *) &client->addr, client->addrlen, 
			client->ip, sizeof (client->ip), NULL, 0, 
			NI_NUMERICHOST);
	if (ret != 0) {
		client_error(client, "accept_client: getnameinfo: %s\n", gai_strerror(ret));
		goto err;
	}

	if (l->ssl_ctx) {
		if ((client->ssl = SSL_new(l->ssl_ctx)) == NULL) {
			client_error(client, "SSL_new: %s",
					ERR_error_string(ERR_get_error(), NULL));
			goto err;
		}

		if (SSL_set_fd(client->ssl, client->fd) != 1) {
			client_error(client, "SSL_set_fd: %s",
					ERR_error_string(ERR_get_error(), NULL));
			goto err;
		}
	}

	if (setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) == -1) {
		client_error(client, "setsockopt(TCP_NODELAY): %s",
				strerror(errno));
		goto err;
	}

	nclients++;
	if (nclients == curconf->maxclients)
		suspend_listeners();

	if (curconf->dodns)
		client_lookup(client);
	else
		client_start(client);

	return;

err:
	if (client)
		client_abort(client);
	else if (cfd != -1)
		close(cfd);
}

void
client_lookup(client_t *client)
{
	switch (client->addr.ss_family) {
	case AF_INET: {
	struct sockaddr_in *addr = (struct sockaddr_in *) &client->addr;
		if (evdns_resolve_reverse(
		    &addr->sin_addr,
		    DNS_QUERY_NO_SEARCH,
		    client_dns_reverse_done,
		    client) == -1) {
			client_error(client, "Reverse DNS lookup failed: %s",
					strerror(errno));
			client_start(client);
		}
		return;
	}

	case AF_INET6: {
	struct sockaddr_in6 *addr = (struct sockaddr_in6 *) &client->addr;
		if (evdns_resolve_reverse_ipv6(
		    &addr->sin6_addr,
		    DNS_QUERY_NO_SEARCH,
		    client_dns_reverse_done,
		    client) == -1) {
			client_error(client, "Reverse DNS lookup failed: %s",
					strerror(errno));
			client_start(client);
		}
		return;
	}

	default:
		client_start(client);
		break;
	}
}

void
client_dns_reverse_done(
	int	 result,
	char	 type,
	int	 count,
	int	 ttl,
	void	*addrs,
	void	*arg
)
{
client_t	*client = arg;

	if (result != DNS_ERR_NONE || count == 0) {
		strlcpy(client->hostname, client->ip, sizeof (client->hostname));
		client_start(client);
		return;
	}

	strlcpy(client->hostname, ((char **)addrs)[0], sizeof (client->hostname));

	switch (client->addr.ss_family) {
	case AF_INET:
		if (evdns_resolve_ipv4(client->hostname,
					DNS_QUERY_NO_SEARCH,
					client_dns_forward_done,
					client) == -1) {
			client_error(client, "Reverse DNS lookup failed: %s",
					strerror(errno));
			strlcpy(client->hostname, client->ip, sizeof (client->hostname));
			client_start(client);
		}
		break;

	case AF_INET6:
		if (evdns_resolve_ipv6(client->hostname,
					DNS_QUERY_NO_SEARCH,
					client_dns_forward_done,
					client) == -1) {
			client_error(client, "Reverse DNS lookup failed: %s",
					strerror(errno));
			strlcpy(client->hostname, client->ip, sizeof (client->hostname));
			client_start(client);
		}
		break;

	default:
		abort();
	}
}

void
client_dns_forward_done(
	int	 result,
	char	 type,
	int	 count,
	int	 ttl,
	void	*addrs,
	void	*arg
)
{
client_t	*client = arg;

	if (result != DNS_ERR_NONE || count == 0) {
		strlcpy(client->hostname, client->ip, sizeof (client->hostname));
		client_start(client);
		return;
	}

	switch (client->addr.ss_family) {
	case AF_INET: {
	struct sockaddr_in *addr = (struct sockaddr_in *) &client->addr;
		if (memcmp(&addr->sin_addr, &((struct in_addr *) addrs)[0],
				sizeof(addr->sin_addr)) != 0)
			strlcpy(client->hostname, client->ip, sizeof (client->hostname));
		client_start(client);
		return;
	}

	case AF_INET6: {
	struct sockaddr_in6 *addr = (struct sockaddr_in6 *) &client->addr;
		if (memcmp(&addr->sin6_addr, &((struct in6_addr *) addrs)[0],
				sizeof(addr->sin6_addr)) != 0)
			strlcpy(client->hostname, client->ip, sizeof (client->hostname));
		client_start(client);
		return;
	}

	default:
	       abort();
	}
}

/* Used for SSL */
void
client_restart(int fd, short what, void *arg)
{
	client_start(arg);
}

void
client_start(client_t *client)
{
int	ret;

	event_set(&client->ev, client->fd, EV_READ, client_read, client);

	if (client->ssl) {
		if ((ret = SSL_accept(client->ssl)) != 1) {
			switch (SSL_get_error(client->ssl, ret)) {
			case SSL_ERROR_WANT_READ:
				event_set(&client->ev, client->fd,
					EV_READ, client_restart, client);
				event_add(&client->ev, &curconf->timeout);
				return;
			case SSL_ERROR_WANT_WRITE:
				event_set(&client->ev, client->fd,
					EV_WRITE, client_restart, client);
				event_add(&client->ev, &curconf->timeout);
				return;
			default:
				client_error(client, "SSL_accept: %s",
					ERR_error_string(ERR_get_error(), NULL));
				client_abort(client);
				return;
			}
		}
	}

	event_add(&client->ev, &curconf->timeout);

	return;

err:
	client_abort(client);
}

/*
 * Client has data waiting.
 */
void
client_read(
	int	 fd,
	short	 what,
	void	*arg
)
{
client_t	*client = arg;
request_t	*req = client->request;
char		*line, *host, *conn;
int		 ret;

	event_set(&client->ev, client->fd, EV_READ, client_read, client);

	if (what == EV_TIMEOUT) {
		client_abort(client);
		return;
	}

	if (client->ssl) {
	char	buf[READ_BUFSZ];
	int	ret, err;
		ret = SSL_read(client->ssl, buf, sizeof (buf));

		if (ret == 0) {
			switch (SSL_get_error(client->ssl, ret)) {
			case SSL_ERROR_WANT_READ:
				event_set(&client->ev, client->fd, EV_READ, client_read, client);
				event_add(&client->ev, &curconf->timeout);
				return;
			case SSL_ERROR_WANT_WRITE:
				event_set(&client->ev, client->fd, EV_WRITE, client_read, client);
				event_add(&client->ev, &curconf->timeout);
				return;
			case SSL_ERROR_ZERO_RETURN:
				SSL_free(client->ssl);
				client->ssl = NULL;
				client_abort(client);
				return;
			default:
				if (SSL_get_shutdown(client->ssl) & SSL_RECEIVED_SHUTDOWN) {
					client_abort(client);
					return;
				}

				if (ERR_get_error() != 0)
					client_error(client, "SSL_read: %s",
						ERR_error_string(ERR_get_error(), NULL));
				client_abort(client);
				return;
			}
		}

		if (ret < 0) {
			client_error(client, "SSL_read: %s",
					ERR_error_string(ERR_get_error(), NULL));
			client_abort(client);
			return;
		}

		evbuffer_add(client->buffer, buf, ret);
		client->request->len += ret;
	} else {
		ret = evbuffer_read(client->buffer, client->fd, READ_BUFSZ);
	
		if (ret == -1 && errno == EAGAIN) {
			event_add(&client->ev, &curconf->timeout);
			return;
		}

		if (ret == -1) {
			client_error(client, "read error: %s", strerror(errno));
			client_abort(client);
			return;
		}

		if (ret == 0) {
			client_abort(client);
			return;
		}

		client->request->len += ret;
	}

	/*
	 * If there's a \r\n\r\n in the buffer, we've read the entire
	 * request.  If not, keep going.
	 */
	if (evbuffer_find(client->buffer, (const u_char *) "\r\n\r\n", 4) == NULL &&
	    evbuffer_find(client->buffer, (const u_char *) "\n\n", 2) == NULL) {
		if (client->request->len > curconf->maxrq) {
			client_send_error(client, HTTP_REQUEST_TOO_LARGE);
			return;
		}

		event_add(&client->ev, &curconf->timeout);
		return;
	}

	if (client->request->len > curconf->maxrq) {
		client_send_error(client, HTTP_REQUEST_TOO_LARGE);
		return;
	}

	if (client_read_request(client) == -1) {
		client_abort(client);
		return;
	}

	while (client->state == READ_HEADERS) {
		if (client_read_header(client) == -1) {
			client_abort(client);
			return;
		}
	}

	/* Determine the vhost based on the Host header */
	if ((host = g_hash_table_lookup(req->headers, "Host")) == NULL)
		host = "_default_";

	if ((req->vhost = config_find_vhost(host)) == NULL) {
		host = "_default_";

		if ((req->vhost = config_find_vhost(host)) == NULL) {
			client_send_error(client, 404);
			return;
		}
	}

	/* Split off the query string */
	if ((req->query = index(req->url, '?')) != NULL)
		*req->query++ = '\0';

	/*
	 * See if we should do keep-alive.
	 */
	/* Default to keep-alive in http/1.1 */
	req->flags.keepalive = req->version == HTTP_11;

	if ((conn = g_hash_table_lookup(req->headers, "Connection")) != NULL) {
	gchar	**opts, *opt;
		opts = g_strsplit(conn, ", ", 0);

		for (opt = *opts; *opt; ++opt) {
			/* In HTTP/1.1, Connection: close disabled keep-alive.
			 * In HTTP/1.0, Connection: Keep-Alive enables it.
			 */
			if (!strcasecmp(opt, "close")) {
				req->flags.keepalive = 0;
				break;
			} else if (!strcasecmp(opt, "Keep-Alive")) {
				req->flags.keepalive = 1;
				break;
			}
		}
		g_strfreev(opts);
	}

	/*
	 * Check if the client wants chunked TE.  We only actually use it
	 * for CGI requests without a content-length.
	 */
	if ((conn = g_hash_table_lookup(req->headers, "TE")) != NULL) {
	gchar	**opts, *opt, *s;
		opts = g_strsplit(conn, ", ", 0);

		for (opt = *opts; *opt; ++opt) {
			if ((s = index(opt, ';')) != NULL)
				*s = '\0';

			if (!strcasecmp(opt, "chunked")) {
				req->flags.accept_chunked = 1;
				break;
			}
		}

		g_strfreev(opts);
	}

	/*
	 * Check if the client can support zlib or gzip compression, but
	 * don't actually enable it yet.
	 */
	if ((conn = g_hash_table_lookup(req->headers, "Accept-Encoding")) != NULL) {
	gchar	**opts, *opt, *s;
		opts = g_strsplit(conn, ", ", 0);

		for (opt = *opts; *opt; ++opt) {
			if ((s = index(opt, ';')) != NULL)
				*s = '\0';

			if (!strcasecmp(opt, "deflate")) {
				req->can_compress = COMP_DEFLATE;
				break;
			} else if (!strcasecmp(opt, "gzip") ||
				   !strcasecmp(opt, "x-gzip")) {
				req->can_compress = COMP_GZIP;
				break;
			}
		}

		g_strfreev(opts);
	}
	assert(client->state == HANDLE_REQUEST);
	handle_file_request(client);
}

int
client_read_header(
	client_t	*client
)
{
char	*header, *value;

	if ((header = evbuffer_readline(client->buffer)) == NULL)
		return -1;

	/* Blank line means end of request */
	if (!*header) {
		client->state = HANDLE_REQUEST;
		return 0;
	}

	if ((value = strstr(header, ": ")) == NULL) {
		/* Invalid header */
		client_abort(client);
		return -1;
	}

	*value = '\0';
	value += 2;
	
	g_hash_table_replace(client->request->headers, header, value);
	return 0;
}

int
client_read_request(
	client_t	*client
)
{
char		*line, *s;
request_t	*req = client->request;

	if ((line = evbuffer_readline(client->buffer)) == NULL)
		return -1;

	/* Read method */
	req->method_str = xstrdup(line);
	if ((req->url = strchr(req->method_str, ' ')) == NULL) {
		/* Invalid request */
		client_abort(client);
		return -1;
	}

	/* Read request URL */
	*req->url++ = '\0';
	if ((s = strchr(req->url, ' ')) == NULL) {
		/* Invalid request */
		client_abort(client);
		return -1;
	}

	/* Read HTTP version */
	*s++ = '\0';
	if (strcmp(s, "HTTP/1.0") == 0)
		req->version = HTTP_10;
	else if (strncmp(s, "HTTP/1.", 7) == 0)
		req->version = HTTP_11;
	else {
		/* Unknown HTTP version */
		client_abort(client);
		return -1;
	}

	if (!strcmp(req->method_str, "GET"))
		req->method = M_GET;
	else if (!strcmp(req->method_str, "PUT"))
		req->method = M_PUT;
	else if (!strcmp(req->method_str, "POST"))
		req->method = M_POST;
	else if (!strcmp(req->method_str, "HEAD"))
		req->method = M_HEAD;
	else
		req->method = M_UNKNOWN;

	client->state = READ_HEADERS;
	return 0;
}

static void
client_reabort(
	int	fd,
	short	what,
	void	*arg
)
{
	client_abort(arg);
}

void
client_abort(client_t *client)
{
	assert(client);

	if (client->ssl) {
	int	ret;
		for (;;) {
			ret = SSL_shutdown(client->ssl);

			if (ret == 1) {
				SSL_free(client->ssl);
				client->ssl = NULL;
				break;
			}

			if (ret == 0)
				break; /*continue;*/

			if (ret < -1) {
				switch (SSL_get_error(client->ssl, ret)) {
				case SSL_ERROR_WANT_READ:
					event_set(&client->ev, client->fd, EV_READ, client_reabort, client);
					event_add(&client->ev, NULL);
					return;
				case SSL_ERROR_WANT_WRITE:
					event_set(&client->ev, client->fd, EV_WRITE, client_reabort, client);
					event_add(&client->ev, NULL);
					return;
				default:
					client_error(client, "SSL_shutdown: %s",
							ERR_error_string(ERR_get_error(), NULL));
					client_abort(client);
					return;
				}
			}
		}
	}

	close(client->fd);

	free_request(client->request);
	evbuffer_free(client->buffer);
	evbuffer_free(client->wrbuf);

	free(client);

	if (nclients == curconf->maxclients)
		start_listeners();
	nclients--;
}

void
client_close(client_t *client)
{
	/*
	 * Finish writing any compressed data.
	 */
	if (client->request->zstream) {
	char	buf[16384];
		client->request->zstream->avail_in = 0;
		client->request->zstream->next_in = 0;

		do {
		size_t	n;
			client->request->zstream->avail_out = sizeof (buf);
			client->request->zstream->next_out = (Byte *) buf;

			deflate(client->request->zstream, Z_FINISH);
			n = sizeof(buf) - client->request->zstream->avail_out;

			if (n) {
				if (client->request->flags.write_chunked)
					evbuffer_add_printf(client->wrbuf, "%lx\r\n",
							(unsigned long) n);

				evbuffer_add(client->wrbuf, buf, n);

				if (client->request->flags.write_chunked)
					evbuffer_add(client->wrbuf, "\r\n", 2);
			}
		} while (client->request->zstream->avail_out == 0);
	}

	if (client->request->flags.write_chunked)
		evbuffer_add(client->wrbuf, "0\r\n\r\n", 5);

	if (client->request->flags.write_chunked ||
	    client->request->zstream) {
		client_drain(client, client_last_chunk_done);
		return;
	}

	client_last_chunk_done(client, 0);
}

void
client_last_chunk_done(
	client_t	*client,
	int		 error
)
{
	if (error) {
		client_error(client, "write error: %s",
				strerror(errno));
		client_abort(client);
		return;
	}

	/*
	 * If we didn't send a content-length and we're not using
	 * chunked encoding, we can't do keep-alive, so abort the
	 * connection.
	 */
	if (!client->request->flags.keepalive ||
	    (!client->request->flags.write_chunked &&
	     g_hash_table_lookup(client->request->resp_headers, "Content-Length") == NULL)) {
		client_abort(client);
		return;
	}

	free_request(client->request);
	client->request = request_new();

	event_set(&client->ev, client->fd, EV_READ, client_read, client);
	event_add(&client->ev, &curconf->timeout);
}

static void
client_drain_ready(
	int	fd,
	short	what,
	void	*arg
)
{
client_t	*client = arg;
int		 ret;

	if (what == EV_TIMEOUT) {
		client_abort(client);
		return;
	}

	if (client->ssl) {
	int	ret;

		if (client->sslbufsz == 0)
			if ((client->sslbufsz = evbuffer_remove(client->wrbuf,
						client->sslbuf,
						sizeof (client->sslbuf))) == 0) {
				client->drain_cb(client, 0);
				return;
			}

		ret = SSL_write(client->ssl, client->sslbuf, client->sslbufsz);

		if (ret == 0) {
			switch (SSL_get_error(client->ssl, ret)) {
			case SSL_ERROR_WANT_READ:
				event_set(&client->ev, client->fd, EV_READ, client_read, client);
				event_add(&client->ev, NULL);
				return;
			case SSL_ERROR_WANT_WRITE:
				event_set(&client->ev, client->fd, EV_WRITE, client_read, client);
				event_add(&client->ev, NULL);
				return;
			default:
				client_error(client, "SSL_write: %s",
						ERR_error_string(ERR_get_error(), NULL));
				client_abort(client);
				return;
			}
		}

		if (ret < 0) {
			client_error(client, "SSL_write: %s",
					ERR_error_string(ERR_get_error(), NULL));
			client_abort(client);
			return;
		}

		client->sslbufsz -= ret;
	} else {
		while ((ret = evbuffer_write(client->wrbuf, client->fd)) > 0)
			;

		if (ret == 0) {
			client->drain_cb(client, 0);
			return;
		}

		if (ret == -1 && errno != EAGAIN)
			client->drain_cb(client, errno);
	}

	event_add(&client->ev, &curconf->timeout);
}

void
client_drain(
	client_t		*client,
	client_drain_callback	 cb
)
{
	assert(client);
	assert(client->wrbuf);

	event_set(&client->ev, client->fd, EV_WRITE,
			client_drain_ready, client);
	client->drain_cb = cb;

	client_drain_ready(client->fd, EV_WRITE, client);
}

void
client_send_error(
	client_t	*client,
	int		 code
)
{
const char	*status;
const char	*body = NULL;

	switch (code) {
	case HTTP_NOT_MODIFIED:
		status = "Not modified";
		break;

	case HTTP_FORBIDDEN:
		status = "Forbidden";
		body = "Access to the requested resource was denied.\n";
		break;

	case HTTP_NOT_FOUND:
		status = "Not found";
		body = "The requested resource was not found "
			"on this server.\n";
		break;

	case HTTP_INTERNAL_SERVER_ERROR:
		status = "Internal server error";
		body = "The server encountered an internal error while "
			"trying to process your request.\n";
		break;

	case HTTP_REQUEST_TOO_LARGE:
		status = "Request too large";
		body = "The request was larger than the configured maximum "
			"request size.\n";
		break;

	case HTTP_LENGTH_REQUIRED:
		status = "Length required";
		body = "The POST request must have a Content-Length header.\n";
		break;

	default:
		abort();
	}

	evbuffer_add_printf(client->wrbuf, 
			"HTTP/1.1 %d %s\r\n"
			"Server: %s\r\n"
			"Date: %s\r\n"
			"Content-Type: text/plain\r\n"
			"Content-Length: %d\r\n\r\n",
			code, status, server_version, current_time,
			body ? (int) strlen(body) : 0);

	if (body)
		evbuffer_add(client->wrbuf, body, strlen(body));

	client_drain(client, error_done);
}

void
client_redirect(
	client_t	*client,
	const char	*where,
	int		 code
)
{
const char	*status;

	switch (code) {
	case HTTP_MOVED_PERMANENTLY:
		status = "Moved permanently";
		break;

	case HTTP_FOUND:
		status = "Found";
		break;

	case HTTP_SEE_OTHER:
		status = "See other";

	case HTTP_TEMPORARY_REDIRECT:
		status = "Temporary redirect";

	default:
		abort();
	}

	evbuffer_add_printf(client->wrbuf, 
			"HTTP/1.1 %d %s\r\n"
			"Server: %s\r\n"
			"Date: %s\r\n"
			"Location: %s\r\n"
			"Content-Type: text/plain\r\n"
			"Content-Length: 0\r\n\r\n",
			code, status, server_version, current_time, where);

	client_drain(client, error_done);
}
void
error_done(
	client_t	*client,
	int		 error
)
{
	client_close(client);
}

void
free_request(request_t *req)
{
	if (!req)
		return;

	g_hash_table_destroy(req->headers);
	g_hash_table_destroy(req->resp_headers);

	evbuffer_free(req->cgi_write_buffer);

	free(req->method_str);
	free(req->filename);
	free(req->username);
	free(req->pathinfo);
	free(req->urlname);

	if (req->zstream) {
		deflateEnd(req->zstream);
		free(req->zstream);
	}

	if (req->fd > 0)
		close(req->fd);

	if (req->fd_write)
		close(req->fd_write);
	if (req->fd_read)
		close(req->fd_read);

	free(req);
}

static void
client_logfmt(
	client_t	*client,
	char		*buf,
	size_t		 bufsz
)
{
	buf[0] = '\0';

	if (client->ip[0]) {
		strlcat(buf, "[Client: ", bufsz);
		strlcat(buf, client->ip, bufsz);
		strlcat(buf, "]", bufsz);
	}

	if (client->request->url) {
		strlcat(buf, "[URL: ", bufsz);
		strlcat(buf, client->request->url, bufsz);
		strlcat(buf, "]", bufsz);
	}

	if (client->request->filename) {
		strlcat(buf, "[File: ", bufsz);
		strlcat(buf, client->request->filename, bufsz);
		strlcat(buf, "]", bufsz);
	}
}

void
client_error(
	client_t	*client,
	const char	*fmt,
	...
)
{
char	cbuf[1024];
char	err[1024];
char	msg[2048];
va_list	ap;
	client_logfmt(client, cbuf, sizeof (cbuf));
	va_start(ap, fmt);
	vsnprintf(err, sizeof (msg), fmt, ap);
	va_end(ap);
	snprintf(msg, sizeof (msg), "%s %s", cbuf, err);
	log_error("%s", msg);
}

void
client_warn(
	client_t	*client,
	const char	*fmt,
	...
)
{
char	cbuf[1024];
char	err[1024];
char	msg[2048];
va_list	ap;
	client_logfmt(client, cbuf, sizeof (cbuf));
	va_start(ap, fmt);
	vsnprintf(msg, sizeof (err), fmt, ap);
	va_end(ap);
	snprintf(msg, sizeof (msg), "%s %s", cbuf, err);
	log_warn("%s", msg);
}

void
client_notice(
	client_t	*client,
	const char	*fmt,
	...
)
{
char	cbuf[1024];
char	err[1024];
char	msg[2048];
va_list	ap;
	client_logfmt(client, cbuf, sizeof (cbuf));
	va_start(ap, fmt);
	vsnprintf(msg, sizeof (err), fmt, ap);
	va_end(ap);
	snprintf(msg, sizeof (msg), "%s %s", cbuf, err);
	log_notice("%s", msg);
}

void
exit_signal(
	int	signal,
	short	what,
	void	*arg
)
{
	log_notice("Exiting on signal");
	event_loopbreak();
}

void
update_time(
	int	fd,
	short	what,
	void	*arg
)
{
time_t		 now;
struct tm	*tm;

	time(&now);
	tm = gmtime(&now);
	strftime(current_time, sizeof (current_time), "%a, %d %b %Y %H:%M:%S GMT", tm);

#ifdef HAVE_SETPROCTITLE
	if (curconf)
		setproctitle("%d/%d clients", nclients, curconf->maxclients);
#endif

	event_add(&ev_time, &one_second);
}

void
net_init(void)
{
time_t		 now;
struct tm	*tm;
	time(&now);
	tm = gmtime(&now);
	strftime(current_time, sizeof (current_time), "%a, %d %b %Y %H:%M:%S GMT", tm);
}

void
client_write(
	client_t	*client,
	const char	*buf,
	size_t		 bufsz
)
{
	if (client->request->compress) {
	char	zbuf[16384];
		client->request->zstream->next_in = (Byte *) buf;
		client->request->zstream->avail_in = bufsz;

		do {
		size_t	n;
			client->request->zstream->avail_out = sizeof (zbuf);
			client->request->zstream->next_out = (Bytef *) zbuf;

			deflate(client->request->zstream, Z_NO_FLUSH);
			n = sizeof(zbuf) - client->request->zstream->avail_out;

			if (n) {
				if (client->request->flags.write_chunked)
					evbuffer_add_printf(client->wrbuf, "%lx\r\n",
							(unsigned long) n);

				evbuffer_add(client->wrbuf, zbuf, n);

				if (client->request->flags.write_chunked)
					evbuffer_add(client->wrbuf, "\r\n", 2);
			}
		} while (client->request->zstream->avail_out == 0);
	} else {
		if (client->request->flags.write_chunked)
			evbuffer_add_printf(client->wrbuf, "%lx\r\n", (long unsigned) bufsz);

		evbuffer_add(client->wrbuf, buf, bufsz);

		if (client->request->flags.write_chunked)
			evbuffer_add(client->wrbuf, "\r\n", 2);
	}
}

void
client_printf(
	client_t	*client,
	const char	*fmt,
	...
)
{
char	*data;
va_list	 ap;

	va_start(ap, fmt);
	data = g_strdup_vprintf(fmt, ap);
	va_end(ap);

	client_write(client, data, strlen(data));
};

void
client_start_response(
	client_t		*client,
	client_drain_callback	 callback)
{
request_t	*req = client->request;
GHashTableIter	 iter;
char		*header, *value;

	/*
	 * If the client requested content compression and the MIME type
	 * is acceptable, start zlib, unless we already sent a different
	 * content-encoding header (e.g. from a CGI script).  Compression
	 * cannot be used with Content-Length, so we remove the CL header.
	 * It will be replaced with chunked TE later if the client
	 * supports it.
	 */
	if (req->can_compress && req->mimetype && curconf->compr_level &&
	    g_hash_table_lookup(req->resp_headers, "Content-Encoding") == NULL) {
	guint   i, end;

		for (i = 0, end = curconf->compr_types->len; i < end; ++i) {
			if (fnmatch(g_ptr_array_index(curconf->compr_types, i),
					req->mimetype, FNM_PATHNAME) == 0) {

				req->zstream = xcalloc(1, sizeof (*req->zstream));

				if (deflateInit2(
				    req->zstream, curconf->compr_level,
				    Z_DEFLATED, req->can_compress == COMP_DEFLATE ? 15 : 31, 
				    8, Z_DEFAULT_STRATEGY) != Z_OK) {
					client_error(client, "Zlib init failed: %s",
						strerror(errno));
					break;
				}

				req->compress = req->can_compress;

				client_add_header(client, "Content-Encoding",
					req->compress == COMP_DEFLATE ?
						"deflate" : "gzip");
				g_hash_table_remove(req->resp_headers,
					"Content-Length");
				break;
			}
		}
	}

	/*
	 * If there's no content-length header, use chunked TE if the
	 * client supports it.
	 */
	if (g_hash_table_lookup(req->resp_headers, "Content-Length") == NULL &&
	    req->flags.accept_chunked) {
		client_add_header(client, "Transfer-Encoding", "chunked");
		req->flags.write_chunked = 1;
	}

	/*
	 * Check if we can support keep-alive for this request.
	 */
	if ((g_hash_table_lookup(req->resp_headers, "Content-Length") != NULL ||
	    req->flags.write_chunked) && req->flags.keepalive) {
		/* HTTP/1.0 clients need a header to indicate we can do keep-alive */
		if (req->version == HTTP_10) {
			client_add_header(client, "Connection", "Keep-Alive");
		}
	} else {
		/* HTTP/1.1 clients need a header to indicate we can't */
		if (req->version == HTTP_11) {
			client_add_header(client, "Connection", "close");
		}
	}

	/*
	 * Add standard headers, unless they're already there.
	 */
	if (g_hash_table_lookup(req->resp_headers, "Server") == NULL)
		client_add_header(client, "Server", server_version);
	if (g_hash_table_lookup(req->resp_headers, "Date") == NULL)
		client_add_header(client, "Date", current_time);

	/*
	 * Write all headers to the client.
	 */
	evbuffer_add_printf(client->wrbuf, "HTTP/1.1 %s\r\n",
			req->resp_status);

	g_hash_table_iter_init(&iter, client->request->resp_headers);

	while (g_hash_table_iter_next(&iter, (gpointer *) &header, (gpointer *) &value))
		evbuffer_add_printf(client->wrbuf, "%s: %s\r\n",
			header, value);

	evbuffer_add_printf(client->wrbuf, "\r\n");
	client_drain(client, callback);

}

void
client_add_header(
	client_t	*client,
	const char	*header,
	const char	*value
)
{
	g_hash_table_replace(client->request->resp_headers,
			xstrdup(header), xstrdup(value));
}

static void
suspend_listeners()
{
guint	i;
	for (i = 0; i < listeners->len; i++)
		event_del(&((listener_t *) g_ptr_array_index(listeners, i))->ev);
}

static void
start_listeners()
{
guint	i;
	for (i = 0; i < listeners->len; i++)
		event_add(&((listener_t *) g_ptr_array_index(listeners, i))->ev, NULL);
}
