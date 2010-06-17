/*
 * Copyright (c) 2010 River Tarnell.  All rights reserved.
 * Use is subject to license terms.
 */

#include	<sys/socket.h>
#include	<netdb.h>
#include	<string.h>
#include	<errno.h>
#include	<unistd.h>
#include	<stdlib.h>
#include	<fcntl.h>
#include	<assert.h>
#include	<stdio.h>

#include	<glib.h>
#include	<event.h>

#include	"net.h"
#include	"config.h"
#include	"log.h"
#include	"file.h"
#include	"setup.h"
#include	"util.h"

static void accept_client(int, short, void *);
static void client_read(int, short, void *);
static void client_write(int, short, void *);
static int client_read_request(client_t *);
static int client_read_header(client_t *);
static void error_done(client_t *, int);
static void exit_signal(int, short, void *);

static GArray	*listeners;

typedef struct {
	int		fd;
	struct event	ev;
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

	if ((fl = fcntl(l->fd, F_GETFL, 0)) == -1) {
		log_error("%s[%s]:%s: fcntl(F_GETFL): %s", 
			conf->addr, nbuf, conf->port, strerror(errno));
		goto err;
	}

	fl |= FD_CLOEXEC | O_NONBLOCK;

	if ((fl = fcntl(l->fd, F_SETFL, fl)) == -1) {
		log_error("%s[%s]:%s: fcntl(F_SETFL): %s", 
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

	event_set(&l->ev, l->fd, EV_READ, accept_client, l);
	event_priority_set(&l->ev, ACCEPT_PRIO);
	event_add(&l->ev, NULL);

	g_array_append_val(listeners, l);
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
	g_array_free(listeners, TRUE);
	return -1;
}

int
net_listen()
{
guint	i;
static struct event ev_sigint;
static struct event ev_sigterm;

	if (event_init() == NULL) {
		log_error("event_init: %s", strerror(errno));
		goto err;
	}

	if (event_priority_init(NPRIOS) == -1) {
		log_error("event_priority_set: %s", strerror(errno));
		goto err;
	}

	if ((listeners = g_array_new(FALSE, FALSE, sizeof(listener_t *))) == NULL)
		goto err;

	for (i = 0; i < curconf->listeners->len; ++i) {
		if (setup_listener(g_array_index(curconf->listeners, tws_listen_t *, i)) == -1)
			goto err;
	}

	event_set(&ev_sigint, SIGINT, EV_SIGNAL, exit_signal, NULL);
	event_set(&ev_sigterm, SIGINT, EV_SIGNAL, exit_signal, NULL);
	event_add(&ev_sigint, NULL);
	event_add(&ev_sigterm, NULL);

	return 0;

err:
	return -1;
}

void
net_run(void)
{
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
	request->headers = g_hash_table_new_full(g_str_hash, g_str_equal, free, NULL);

	return request;
}

void
accept_client(
	int	 fd,
	short	 ev,
	void	*arg
)
{
int		 cfd = -1, ret;
listener_t	*l = arg;
client_t	 *client = NULL;

struct sockaddr_storage	addr;
socklen_t		addrlen = sizeof(addr);

	event_add(&l->ev, NULL);

	if ((cfd = accept(fd, (struct sockaddr *) &addr, &addrlen)) == -1) {
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

	bcopy(&addr, &client->addr, sizeof(addr));
	client->addrlen = addrlen;
	client->state = READ_REQUEST;

	ret = getnameinfo((struct sockaddr *) &client->addr, client->addrlen, 
			client->ip, sizeof (client->ip), NULL, 0, 
			NI_NUMERICHOST);
	if (ret != 0) {
		log_error("accept_client: getnameinfo: %s\n", gai_strerror(ret));
		goto err;
	}

	event_set(&client->ev, client->fd, EV_READ, client_read, client);
	event_add(&client->ev, NULL);

	return;

err:
	if (cfd != -1)
		close(cfd);
	if (client)
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

	ret = evbuffer_read(client->buffer, client->fd, READ_BUFSZ);
	
	if (ret == -1 && errno == EAGAIN) {
		event_add(&client->ev, NULL);
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

	/*
	 * If there's a \r\n\r\n in the buffer, we've read the entire
	 * request.  If not, keep going.
	 */
	if (evbuffer_find(client->buffer, (const u_char *) "\r\n\r\n", 4) == NULL) {
		event_add(&client->ev, NULL);
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
	 * See if we should do keep-alive.  HTTP/1.1 only.
	 */
	if (req->version == HTTP_11) {
		client->request->keepalive = 1;

		if ((conn = g_hash_table_lookup(req->headers, "Connection")) != NULL) {
		gchar	**opts, *opt;
			opts = g_strsplit(conn, ", ", 0);
			for (opt = *opts; *opt; ++opt)
				if (!strcasecmp(opt, "close")) {
					client->request->keepalive = 0;
					break;
				}
			g_strfreev(opts);
		}
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
	req->method_str = strdup(line);
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

/*
 * Ready to write more data to the client.
 */
void
client_write(
	int	 fd,
	short	 what,
	void	*arg
)
{
client_t	*cli = arg;
}

void
client_abort(client_t *client)
{
	assert(client);

	close(client->fd);

	free_request(client->request);
	evbuffer_free(client->buffer);
	evbuffer_free(client->wrbuf);

	free(client);
}

void
client_close(client_t *client)
{
	if (!client->request->keepalive) {
		client_abort(client);
		return;
	}

	free_request(client->request);
	client->request = request_new();

	event_set(&client->ev, client->fd, EV_READ, client_read, client);
	event_add(&client->ev, NULL);
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

	if ((ret = evbuffer_write(client->wrbuf, client->fd)) > 0) {
		event_del(&client->ev);
		client->drain_cb(client, 0);
		return;
	}

	if (ret == -1 && errno != EAGAIN)
		client->drain_cb(client, errno);
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
	event_add(&client->ev, NULL);
	client->drain_cb = cb;

/*	client_drain_ready(client->fd, EV_WRITE, client);*/
}

void
client_send_error(
	client_t	*client,
	int		 code
)
{
const char	*status;
const char	*body = NULL;
time_t		 now;
struct tm	*tm;
char		 tbuf[64];

	switch (code) {
	case 304:
		status = "Not modified";
		break;

	case 403:
		status = "Forbidden";
		body = "Access to the requested resource was denied.\n";
		break;

	case 404:
		status = "Not found";
		body = "The requested resource was not found "
			"on this server.\n";
		break;

	case 500:
		status = "Internal server error";
		body = "The server encountered an internal error while "
			"trying to process your request.\n";
		break;

	default:
		status = "Unknown";
		body = "An unknown error occurred.\n";
		break;
	}

	time(&now);
	tm = gmtime(&now);
	strftime(tbuf, sizeof (tbuf), "%b, %d %a %Y %H:%M:%S GMT", tm);

	evbuffer_add_printf(client->wrbuf, 
			"HTTP/%s %d %s\r\n"
			"Server: Toolserver-Web-Server/%s\r\n"
			"Date: %s\r\n"
			"Content-Type: text/plain\r\n"
			"Content-Length: %d\r\n\r\n",
			client->request->version == HTTP_10 ? "1.0" : "1.1",
			code, status, PACKAGE_VERSION, tbuf,
			body ? (int) strlen(body) : 0);

	if (body)
		evbuffer_add(client->wrbuf, body, strlen(body));

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

	if (req->headers)
		g_hash_table_destroy(req->headers);

	free(req->method_str);
	free(req->filename);
	free(req->username);
	free(req->pathinfo);
	free(req->urlname);

	if (req->fd)
		close(req->fd);

	if (req->fds[0])
		close(req->fds[0]);
	if (req->fds[1])
		close(req->fds[1]);
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
