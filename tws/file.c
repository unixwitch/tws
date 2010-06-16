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

static void free_request(file_request_t *);

#ifdef USE_SENDFILE
static void sendfile_callback(int, short, void *);
#endif
static void write_callback(client_t *, int);
static void headers_done(client_t *, int);
static void error_done(client_t *, int);
static char *get_filename(request_t *, file_request_t *, vhost_t *);
static char *get_userdir(request_t *, file_request_t *, vhost_t *);

void
handle_file_request(
	client_t	*client
)
{
request_t	*req = client->request;
const char	*host;
file_request_t	*freq = NULL;
struct stat	 sb;
char		*path, *end, *s, *t, *ext;
int		 iscgi = 0;
time_t		 now;
struct tm	*tm;
char		 tbuf[64];

	if ((freq = calloc(1, sizeof (*freq))) == NULL) {
		log_error("handle_file_request: calloc: %s", strerror(errno));
		client_error(client, 500);
		return;
	}
	client->hdldata = freq;

	if ((host = g_hash_table_lookup(req->headers, "Host")) == NULL)
		host = "_default_";

	if ((freq->vhost = config_find_vhost(host)) == NULL) 
		host = "_default_";

	if ((freq->vhost = config_find_vhost(host)) == NULL) {
		client_error(client, 404);
		return;
	}

	if ((freq->query = index(req->url, '?')) != NULL)
		*freq->query++ = '\0';

	if ((freq->filename = get_filename(req, freq, freq->vhost)) == NULL) {
		client_error(client, 500);
		return;
	}

	/*
	 * Traverse the filename, and check each component of the path.  If
	 * we end up at a file, the remainder of the URL is path info.
	 */
	if ((path = strdup(freq->filename)) == NULL) {
		log_error("handle_file_request: strdup: %s", strerror(errno));
		client_error(client, 500);
		return;
	}

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

		fprintf(stderr, "component: [%s]\n", s);
		if (stat(s, &sb) == -1) {
			log_error("handle_file_request: %s: %s",
				s, strerror(errno));

			switch (errno) {
			case EACCES:
				client_error(client, 403);
				return;
			default:
				client_error(client, 404);
				return;
			}
		}

		if ((u = rindex(s, '/')) && !strcmp(u, "/..")) {
			client_error(client, 404);
			return;
		}

		if (!S_ISDIR(sb.st_mode)) {
			if (t != end) {
				if ((freq->pathinfo = strdup(freq->filename + strlen(s))) == NULL) {
					log_error("handle_file_request: strdup: %s",
							strerror(errno));
					client_error(client, 500);
					return;
				}
				fprintf(stderr, "path info: [%s]\n", freq->pathinfo);
			}

			free(freq->filename);
			freq->filename = s;

			/* Identify the MIME type */
			if ((ext = rindex(s, '.')) != NULL &&
			    ext > rindex(s, '/')) {
				fprintf(stderr, "ext [%s]\n", ext);
				freq->mimetype = g_hash_table_lookup(
					curconf->mimetypes, ext + 1);
			}

			break;
		}

		if (g_hash_table_lookup_extended(freq->vhost->cgidirs, s, NULL, NULL))
			iscgi = 1;

next:
		/* Move to the next component */
		if (t == end || !t)
			break;

		*t = '/';
		while (*t == '/')
			t++;
	}

	if (g_hash_table_lookup_extended(freq->vhost->cgitypes, freq->mimetype, NULL, NULL))
		iscgi = 1;

	if (iscgi) {
		fprintf(stderr, "execute CGI: %s\n", freq->filename);
		handle_cgi_request(client, freq);
		return;
	}

	if ((freq->fd = open(freq->filename, O_RDONLY)) == -1) {
		log_error("%s: %s", freq->filename, strerror(errno));

		switch (errno) {
		case EACCES:
			client_error(client, 403);
			break;

		/*
		 * We return 404 for any other error.  It could be caused by
		 * many things other than file not found (e.g. I/O error),
		 * but in the end, they all mean that we couldn't find the
		 * file.
		 */
		default:
			client_error(client, 404);
			break;
		}

		return;
	}

	if (fstat(freq->fd, &sb) == -1) {
		log_error("%s: %s", freq->filename, strerror(errno));
		client_close(client);
		return;
	}

	if (!S_ISREG(sb.st_mode)) {
		log_error("%s: is not a regular file", freq->filename);
		client_close(client);
		return;
	}

	freq->bytesleft = sb.st_size;

	evbuffer_add_printf(client->wrbuf, "HTTP/%s 200 OK\r\n",
			req->version == HTTP_10 ? "1.0" : "1.1");
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

	if (freq->mimetype)
		evbuffer_add_printf(client->wrbuf,
			"Content-Type: %s\r\n",
			freq->mimetype);
	else if (freq->vhost->deftype)
		evbuffer_add_printf(client->wrbuf,
			"Content-Type: %s\r\n",
			freq->vhost->deftype);
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
		log_error("write: %s", strerror(error));
		free_request(client->hdldata);
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
file_request_t	*freq = client->hdldata;

	ret = sendfile(freq->fd, client->fd, freq->bytesdone, 
			freq->bytesleft, NULL, &done, 0);

	if (ret == 0) {
		free_request(freq);
		client_close(client);
		return;
	}

	if (ret == -1 && errno == EAGAIN) {
		freq->bytesdone += done;
		freq->bytesleft -= done;
		event_add(&client->ev, NULL);
		return;
	}

	log_error("%s: sendfile: %s", freq->filename, strerror(errno));
	free_request(freq);
	client_close(client);
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
file_request_t	*freq = client->hdldata;
char		 buf[4096];
ssize_t		 n;
	
	n = read(freq->fd, buf, sizeof(buf));
	if (n == -1) {
		log_error("%s: read: %s", freq->filename, strerror(errno));
		free_request(freq);
		client_close(client);
		return;
	}

	if (n == 0) {
		free_request(freq);
		client_close(client);
		return;
	}

	evbuffer_add(client->wrbuf, buf, n);
	client_drain(client, write_callback);
}

void
free_request(
	file_request_t	*req
)
{
	if (!req)
		return;

	free(req->filename);
	free(req->username);
	free(req->pathinfo);
	free(req->urlname);
	close(req->fd);
	free(req);
}

char *
get_filename(
	request_t	*req,
	file_request_t	*freq,
	vhost_t		*vhost
)
{
char	*fname;

	if (vhost->userdir) {
		if ((fname = get_userdir(req, freq, vhost)) != NULL)
			return fname;
	}

	if ((fname = malloc(strlen(vhost->docroot) + 1 + strlen(req->url) + 1)) == NULL) {
		log_error("get_filename: malloc: %s", strerror(errno));
		return NULL;
	}

	sprintf(fname, "%s/%s", vhost->docroot, req->url + 1);
	if ((freq->urlname = strdup(req->url + 1)) == NULL) {
		log_error("get_filename: strdup: %s", strerror(errno));
		return NULL;
	}

	return fname;
}

char *
get_userdir(
	request_t	*req,
	file_request_t	*freq,
	vhost_t		*vhost
)
{
struct passwd	*pwd;
char		*uname, *s, *fname;

	if (strncmp(req->url, vhost->userdir_prefix, strlen(vhost->userdir_prefix)) != 0 ||
	    strlen(req->url) <= strlen(vhost->userdir_prefix))
		return NULL;

	/* The URL form is <prefix><username>[/] */
	if ((uname = strdup(req->url + strlen(vhost->userdir_prefix))) == NULL) {
		log_error("get_userdir: strdup: %s", strerror(errno));
		return NULL;
	}

	if ((s = strchr(uname, '/')) != NULL)
		*s++ = '\0';

	if ((freq->username = strdup(uname)) == NULL) {
		log_error("get_userdir: strdup: %s", strerror(errno));
		return NULL;
	}
	freq->userdir = 1;

	if ((pwd = getpwnam(uname)) == NULL) {
		free(uname);
		return NULL;
	}

	if ((fname = malloc(
			strlen(pwd->pw_dir) + 1 +
			strlen(s) + 1)) == NULL) {
		log_error("get_userdir: malloc: %s", strerror(errno));
		free(uname);
		return NULL;
	}

	sprintf(fname, "%s/%s/%s",
			pwd->pw_dir,
			vhost->userdir,
			s);
	if ((freq->urlname = strdup(s)) == NULL) {
		log_error("get_userdir: strdup: %s", strerror(errno));
		free(uname);
		return NULL;
	}

	free(uname);
	return fname;
}
