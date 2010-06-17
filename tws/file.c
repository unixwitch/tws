/*
 * Copyright (c) 2010 River Tarnell.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Handle static file requests.  If a file turns out to be a CGI
 * request, pass it off to the CGI handler.
 */

#include	<sys/types.h>
#include	<sys/stat.h>
#include	<unistd.h>
#include	<fcntl.h>
#include	<errno.h>
#include	<string.h>
#include	<stdlib.h>
#include	<stdio.h>
#include	<pwd.h>

#include	<glib.h>

#include	"file.h"
#include	"config.h"
#include	"net.h"
#include	"log.h"
#include	"cgi.h"
#include	"setup.h"
#include	"util.h"

#ifdef USE_SENDFILE
static void sendfile_callback(int, short, void *);
#endif
static void write_callback(client_t *, int);
static void headers_done(client_t *, int);
static void error_done(client_t *, int);
static char *get_filename(request_t *);
static char *get_userdir(request_t *);

void
handle_file_request(
	client_t	*client
)
{
request_t	*req = client->request;
const char	*host;
struct stat	 sb;
char		*path, *end, *s, *t, *ext;
int		 iscgi = 0;
time_t		 now;
struct tm	*tm;
char		 tbuf[64];
char		*ims;

	/*
	 * Transform the filename into either a docroot or userdir request.
	 */
	if ((req->filename = get_filename(req)) == NULL) {
		client_send_error(client, 500);
		return;
	}

	/*
	 * Traverse the filename, and check each component of the path.  If
	 * we end up at a file, the remainder of the URL is path info.
	 */
	path = xstrdup(req->filename);
	end = path + strlen(path);
	s = t = path;
	for (;;) {
	struct stat	 sb;
	char		*u;
		t = strchr(t, '/');
		if (t)
			*t = '\0';

		if (!*s)
			/* Empty component */
			goto next;

		if (stat(s, &sb) == -1) {
			client_error(client, "%s: %s",
				s, strerror(errno));

			switch (errno) {
			case EACCES:
				client_send_error(client, 403);
				return;
			default:
				client_send_error(client, 404);
				return;
			}
		}

		if ((u = rindex(s, '/')) && !strcmp(u, "/..")) {
			client_send_error(client, 404);
			return;
		}

		/*
		 * Found a file.  If there's any more URL left, turn it into
		 * path info for CGI requests.
		 */
		if (!S_ISDIR(sb.st_mode)) {
			if (t && t != end) {
				/*
				 * Request has pathinfo; store it in req and remove it
				 * from urlname.
				 */
				req->pathinfo = xstrdup(req->filename + strlen(s));
				*t = '\0';
				req->urlname[strlen(req->urlname) - strlen(req->pathinfo)] = '\0';
			}

			free(req->filename);
			req->filename = s;

			/* Identify the MIME type */
			if ((ext = rindex(s, '.')) != NULL &&
			    ext > rindex(s, '/')) {
				req->mimetype = g_hash_table_lookup(
					curconf->mimetypes, ext + 1);
			}

			break;
		}

		/*
		 * If we're now inside a CGI directory, mark this as a CGI request.
		 */
		if (g_hash_table_lookup_extended(req->vhost->cgidirs, s, NULL, NULL))
			iscgi = 1;

next:
		/* Move to the next component */
		if (t == end || !t)
			break;

		*t = '/';
		while (*t == '/')
			t++;
	}

	/*
	 * Check if the MIME type forces this to be a CGI request.  If so,
	 * pass it off to the CGI handler.
	 */
	if (g_hash_table_lookup_extended(req->vhost->cgitypes, req->mimetype, NULL, NULL))
		iscgi = 1;

	if (iscgi) {
		/* Our work here is done */
		handle_cgi_request(client);
		return;
	}

	/* We only support GET and HEAD for files */
	if (req->method != M_GET && req->method != M_HEAD) {
		client_send_error(client, 403);
		return;
	}

	if ((req->fd = open(req->filename, O_RDONLY)) == -1) {
		client_error(client, "%s", strerror(errno));

		switch (errno) {
		case EACCES:
			client_send_error(client, 403);
			break;

		/*
		 * We return 404 for any other error.  It could be caused by
		 * many things other than file not found (e.g. I/O error),
		 * but in the end, they all mean that we couldn't find the
		 * file.
		 */
		default:
			client_send_error(client, 404);
			break;
		}

		return;
	}

	if (fstat(req->fd, &sb) == -1) {
		client_error(client, "%s", strerror(errno));
		client_send_error(client, 404);
		return;
	}

	if (!S_ISREG(sb.st_mode)) {
		client_error(client, "not a regular file");
		client_send_error(client, 403);
		return;
	}

	/* Check for If-Modified-Since */
	if ((ims = g_hash_table_lookup(req->headers, "If-Modified-Since")) != NULL) {
	struct tm	stm;
		if (strptime(ims, "%b, %d %a %Y %H:%M:%S GMT", &stm) != NULL) {
			if (timegm(&stm) >= sb.st_mtime) {
				client_send_error(client, 304);
				return;
			}
		}
	}

	req->bytesleft = sb.st_size;

	evbuffer_add_printf(client->wrbuf, "HTTP/1.1 200 OK\r\n");
	evbuffer_add_printf(client->wrbuf, "Server: Toolserver-Web-Server/%s\r\n",
			PACKAGE_VERSION);
	evbuffer_add_printf(client->wrbuf, "Content-Length: %lu\r\n",
			(long unsigned) sb.st_size);

	time(&now);
	tm = gmtime(&now);
	strftime(tbuf, sizeof (tbuf), "%b, %d %a %Y %H:%M:%S GMT", tm);
	evbuffer_add_printf(client->wrbuf, "Date: %s\r\n", tbuf);

	if (sb.st_mtime > now)
		sb.st_mtime = now;

	tm = gmtime(&sb.st_mtime);
	strftime(tbuf, sizeof (tbuf), "%b, %d %a %Y %H:%M:%S GMT", tm);
	evbuffer_add_printf(client->wrbuf, "Last-Modified: %s\r\n", tbuf);

	if (req->version == HTTP_10 && req->keepalive)
		evbuffer_add_printf(client->wrbuf,
				"Connection: Keep-Alive\r\n");

	if (req->mimetype)
		evbuffer_add_printf(client->wrbuf,
			"Content-Type: %s\r\n",
			req->mimetype);
	else if (req->vhost->deftype)
		evbuffer_add_printf(client->wrbuf,
			"Content-Type: %s\r\n",
			req->vhost->deftype);
	else if (curconf->deftype)
		evbuffer_add_printf(client->wrbuf,
			"Content-Type: %s\r\n",
			curconf->deftype);

	evbuffer_add(client->wrbuf, "\r\n", 2);
	client_drain(client, headers_done);
}

void
headers_done(
	client_t	*client,
	int		 error
)
{
	if (error) {
		client_error(client, "write: %s", strerror(error));
		client_close(client);
		return;
	}

	/*
	 * For a HEAD request, we're done after writing the headers.
	 */
	if (client->request->method == M_HEAD) {
		client_close(client);
		return;
	}

#ifdef USE_SENDFILE
	if (curconf->use_sendfile) {
		event_set(&client->ev, client->fd, EV_WRITE, sendfile_callback, client);
		sendfile_callback(client->fd, EV_WRITE, client);
	} else
#endif
		write_callback(client, 0);
}

#ifdef USE_SENDFILE
static void
sendfile_callback(
	int	fd,
	short	what,
	void	*arg
)
{
client_t	*client = arg;
int		 ret;
off_t		 done;

	ret = sendfile(client->request->fd, client->fd, client->request->bytesdone, 
			client->request->bytesleft, NULL, &done, 0);

	/* Write done */
	if (ret == 0) {
		client_close(client);
		return;
	}

	if (ret == -1 && errno == EAGAIN) {
		client->request->bytesdone += done;
		client->request->bytesleft -= done;
		event_add(&client->ev, NULL);
		return;
	}

	/* Write error, abort the client */
	client_error(client, "sendfile: %s", strerror(errno));
	client_abort(client);
	return;
}
#endif

static void
write_callback(
	client_t	*client,
	int		 error
)
{
int		 ret;
off_t		 done;
char		 buf[4096];
ssize_t		 n;
	
	n = read(client->request->fd, buf, sizeof (buf));
	if (n == -1) {
		client_error(client, "read: %s", strerror(errno));
		client_abort(client);
		return;
	}

	if (n == 0) {
		client_close(client);
		return;
	}

	evbuffer_add(client->wrbuf, buf, n);
	client_drain(client, write_callback);
}

char *
get_filename(request_t *req)
{
char	*fname;

	if (req->vhost->userdir) {
		if ((fname = get_userdir(req)) != NULL)
			return fname;
	}

	fname = xmalloc(strlen(req->vhost->docroot) + 1 + strlen(req->url) + 1);
	sprintf(fname, "%s/%s", req->vhost->docroot, req->url + 1);

	req->urlname = strdup(req->url + 1);

	return fname;
}

char *
get_userdir(request_t *req)
{
struct passwd	*pwd;
char		*uname, *s, *fname;

	if (strncmp(req->url, req->vhost->userdir_prefix, strlen(req->vhost->userdir_prefix)) != 0 ||
	    strlen(req->url) <= strlen(req->vhost->userdir_prefix))
		return NULL;

	/* The URL form is <prefix><username>[/] */
	uname = xstrdup(req->url + strlen(req->vhost->userdir_prefix));

	if ((s = strchr(uname, '/')) != NULL)
		*s++ = '\0';

	req->username = strdup(uname);
	req->userdir = 1;

	if ((pwd = getpwnam(uname)) == NULL) {
		free(uname);
		return NULL;
	}

	fname = xmalloc(strlen(pwd->pw_dir) + 1 + 
			strlen(req->vhost->userdir) + 1 + strlen(s) + 1);

	sprintf(fname, "%s/%s/%s",
			pwd->pw_dir,
			req->vhost->userdir,
			s);
	req->urlname = xstrdup(s);

	free(uname);
	return fname;
}
