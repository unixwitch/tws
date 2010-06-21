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
#include	<fnmatch.h>
#include	<dirent.h>

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
static void handle_directory(client_t *);

#define OPEN_FLAGS (O_RDONLY | O_NOCTTY | O_NONBLOCK)

/*
 * Simple non-reentrant path iterator.  Returns each component in
 * 'path'.
 */
char *
path_iterate(const char *path, const char **pos)
{
static const char       *arg = NULL, *part;
static char             *comp = NULL;
static int               done = 0;
char                    *s;
ptrdiff_t                len;

        if (!path) {
                free(comp);
		arg = comp = NULL;
		done = 0;
		return NULL;
	}

	if (path != arg) {
                arg = part = path;
                done = 0;
                comp = malloc(strlen(path) + 1);
                if (*part == '/')
                        part++;
	}

        if (done)
                return NULL;

        if ((s = index(part, '/')) == NULL) {
		if (pos)
			*pos = part;

                done = 1;
                strcpy(comp, part);
                return comp;
        }

	if (pos)
		*pos = part;

        len = s - part;
        memcpy(comp, part, len);
        comp[len] = '\0';

        while (*s == '/')
                s++;

        if (*s == '\0')
                done = 1;

        part = s;
        return comp;
}

static int
traverse(
	client_t	*client,
	request_t	*req,
	struct stat	*sb,
	int		*iscgi
)
{
char		*part;
const char	*pos;
int		 cd = -1, cur = -1;

	if ((cd = open("/", OPEN_FLAGS)) == -1) {
		client_error(client, "open(/): %s", strerror(errno));
		client_send_error(client, HTTP_NOT_FOUND);
		return -1;
	}

	path_iterate(NULL, NULL);
	while ((part = path_iterate(req->filename, &pos)) != NULL) {
	char		*u;

		if (!strcmp(part, "..")) {
			client_send_error(client, HTTP_NOT_FOUND);
			goto err;
		}

		if ((cur = openat(cd, part, OPEN_FLAGS)) == -1) {
			client_error(client, "%s", strerror(errno));

			switch (errno) {
			case EACCES:
				client_send_error(client, HTTP_FORBIDDEN);
				goto err;

			default:
				client_send_error(client, HTTP_NOT_FOUND);
				goto err;
			}
		}

		if (fstat(cur, sb) == -1) {
			client_error(client, "fstat: %s", strerror(errno));
			client_send_error(client, HTTP_NOT_FOUND);
			goto err;
		}

		/*
		 * Found a file.  If there's any more URL left, turn it into
		 * path info for CGI requests.
		 */
		if (!S_ISDIR(sb->st_mode)) {
		char		*ext;
		const char	*pi;

			if (path_iterate(req->filename, &pi)) {
				/*
				 * Request has pathinfo; store it in req and remove it
				 * from urlname.
				 */
				req->pathinfo = xstrdup(pi - 1);
				req->urlname[strlen(req->urlname) - strlen(req->pathinfo)] = '\0';
			}

			close(cd);
			break;
		}

		/*
		 * If we're now inside a CGI directory, mark this as a CGI request.
		 */
#if 0
		if (g_hash_table_lookup_extended(req->vhost->cgidirs, s, NULL, NULL))
			*iscgi = 1;
#endif

		close(cd);
		cd = cur;
		cur = -1;
	}

	return cur == -1 ? cd : cur;

err:
	if (cd != -1)
		close(cd);
	if (cur != -1)
		close(cur);
	return -1;
}

static int
get_pathname(
	client_t	*client,
	request_t	*req
)
{
	/*
	 * Transform the filename into either a docroot or userdir request.
	 * We also set 'urlname' here.  This is the part of the URL excluding
	 * the leading /; and for userdir requests, excluding the leading
	 * userdir prefix.  Example:
	 *   /foo/bar/baz  -> foo/bar/baz
	 *   /~foo/bar/baz -> bar/baz
	 * The urlname is used later in suexec CGI processing.
	 */
	
	if (req->vhost->userdir &&
	    strncmp(req->url, req->vhost->userdir_prefix, strlen(req->vhost->userdir_prefix)) == 0 &&
	    strlen(req->url) > strlen(req->vhost->userdir_prefix)) {
	char	*s;
		/* This is a userdir request */
		if ((req->filename = get_userdir(req)) == NULL) {
			client_send_error(client, HTTP_BAD_REQUEST);
			return -1;
		}
		if ((s = index(req->url + strlen(req->vhost->userdir_prefix), '/')) != NULL)
			req->urlname = xstrdup(s + 1);
	} else {
		if ((req->filename = get_filename(req)) == NULL) {
			client_send_error(client, HTTP_BAD_REQUEST);
			return -1;
		}
		req->urlname = xstrdup(req->url + 1);
	}

	return 0;
}

void
handle_file_request(
	client_t	*client
)
{
request_t	*req = client->request;
const char	*host;
struct stat	 sb;
char		*s;
int		 iscgi = 0;
time_t		 now;
struct tm	*tm;
char		 tbuf[64], clen[64];
char		*ims, *ext;

	if (get_pathname(client, req) == -1)
		goto err;

	s = g_uri_unescape_string(req->filename, NULL);
	free(req->filename);
	req->filename = s;

	/*
	 * Traverse the filename to find which file the URL refers to.
	 */
	if ((req->fd = traverse(client, req, &sb, &iscgi)) == -1)
		goto err;

	fd_set_cloexec(req->fd);

	/*
	 * If filename is a directory, check for a directory index.
	 */
	if (S_ISDIR(sb.st_mode)) {
	guint	i;
	int	have_index = 0;

		/* Redirect /dir to /dir/ */
		if (req->url[strlen(req->url) - 1] != '/') {
		char	*rdname = xmalloc(strlen(req->url) + 2);

			sprintf(rdname, "%s/", req->url);
			client_redirect(client, rdname, HTTP_MOVED_PERMANENTLY);
			free(rdname);
			goto err;
		}

		/*
		 * Look for a directory index.
		 */
		for (i = 0; i < req->vhost->indexes->len; ++i) {
		char	*index = g_ptr_array_index(req->vhost->indexes, i);
		int	 newfd;
		char	*fn;

			if ((newfd = openat(req->fd, index, OPEN_FLAGS)) == -1) {
				if (errno != ENOENT) {
					client_error(client, "%s: %s",
						index, strerror(errno));
					client_send_error(client, HTTP_NOT_FOUND);
					goto err;
				}

				continue;
			}

			fd_set_cloexec(newfd);

			close(req->fd);
			req->fd = newfd;
			if (fstat(req->fd, &sb) == -1) {
				client_error(client, "%s: fstat: %s",
					index, strerror(errno));
				client_send_error(client, HTTP_NOT_FOUND);
				goto err;
			}

			fn = g_strdup_printf("%s%s", req->filename, index);
			free(req->filename);
			req->filename = fn;
			have_index = 1;
			break;
		}
			
		if (!have_index) {
			handle_directory(client);
			goto err;
		}
	}

	/* Look for MIME type */
	if ((ext = rindex(req->filename, '.')) != NULL && ext > rindex(req->filename, '/'))
		req->mimetype = g_hash_table_lookup(curconf->mimetypes, ext + 1);

	if (req->mimetype)
		if (g_hash_table_lookup_extended(req->vhost->cgitypes, req->mimetype, NULL, NULL))
			iscgi = 1;
		else if (g_hash_table_lookup(req->vhost->interps, req->mimetype))
			iscgi = 1;

	if (iscgi) {
		/* Our work here is done */
		close(req->fd);
		req->fd = -1;
		handle_cgi_request(client);
		goto err;
	}

	/* We only support GET and HEAD for files */
	if (req->method != M_GET && req->method != M_HEAD) {
		client_send_error(client, HTTP_FORBIDDEN);
		goto err;
	}

	if (!S_ISREG(sb.st_mode)) {
		client_error(client, "not a regular file");
		client_send_error(client, HTTP_FORBIDDEN);
		goto err;
	}

	/* Check for If-Modified-Since */
	if ((ims = g_hash_table_lookup(req->headers, "If-Modified-Since")) != NULL) {
	struct tm	stm;
		if (strptime(ims, "%b, %d %a %Y %H:%M:%S GMT", &stm) != NULL) {
			if (timegm(&stm) >= sb.st_mtime) {
				client_send_error(client, HTTP_NOT_MODIFIED);
				goto err;
			}
		}
	}

	req->bytesleft = sb.st_size;

	req->resp_status = xstrdup("200 OK");

	snprintf(clen, sizeof (clen), "%lu", (long unsigned) sb.st_size);
	client_add_header(client, "Content-Length", clen);

	time(&now);
	if (sb.st_mtime > now)
		sb.st_mtime = now;

	tm = gmtime(&sb.st_mtime);
	strftime(tbuf, sizeof (tbuf), "%b, %d %a %Y %H:%M:%S GMT", tm);
	client_add_header(client, "Last-Modified", tbuf);

	if (req->mimetype)
		client_add_header(client, "Content-Type", req->mimetype);
	else if (req->vhost->deftype)
		client_add_header(client, "Content-Type", req->vhost->deftype);
	else if (curconf->deftype)
		client_add_header(client, "Content-Type", curconf->deftype);

	client_start_response(client, headers_done);
	return;

err:
	return;
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

	/* sendfile cannot be used with compression or encryption */
#ifdef USE_SENDFILE
	if (curconf->use_sendfile && !client->request->compress && !client->ssl) {
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
static char	 buf[1024 * 256];
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

	client_write(client, buf, n);
	client_drain(client, write_callback);
}

char *
get_filename(request_t *req)
{
char	*fname;

	fname = xmalloc(strlen(req->vhost->docroot) + 1 + strlen(req->url) + 1);
	sprintf(fname, "%s/%s", req->vhost->docroot, req->url + 1);

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

	req->username = xstrdup(uname);
	req->flags.userdir = 1;

	if ((pwd = getpwnam(uname)) == NULL) {
		free(uname);
		return NULL;
	}

	fname = xmalloc(strlen(pwd->pw_dir) + 1 + 
			strlen(req->vhost->userdir) + 1 +
			(s ? strlen(s) : 0) + 1);

	if (s)
		sprintf(fname, "%s/%s/%s",
				pwd->pw_dir,
				req->vhost->userdir,
				s);
	else
		sprintf(fname, "%s/%s",
				pwd->pw_dir,
				req->vhost->userdir);

	free(uname);
	return fname;
}

typedef struct direntry {
	char	*name;
	time_t	 mtime;
	int	 isdir;
	off_t	 size;
} direntry_t;

static int
dircmp(gconstpointer a, gconstpointer b)
{
const direntry_t	*da = a, *db = b;
	return strcmp(da->name, db->name);
}

static void
dir_write_done(client_t *client, int error)
{
	if (error) {
		client_error(client, "write: %s",
				strerror(error));
		client_abort(client);
		return;
	}

	client_close(client);
}

static void
dir_start_write(client_t *client, int error)
{
GArray		*dirents = NULL;
DIR		*dir = NULL;
struct dirent	*de;
guint		 i, end;
char		*escurl;

	if (error) {
		client_error(client, "write: %s", strerror(errno));
		client_abort(client);
		return;
	}

	if ((dir = fdopendir(client->request->fd)) == NULL) {
		client_error(client, "fdopendir: %s", strerror(errno));
		goto err;
	}

	dirents = g_array_new(FALSE, FALSE, sizeof (direntry_t));

	escurl = htmlescape(client->request->url);
	client_printf(client,
"<!DOCTYPE html>"
"<html>\n"
"  <head>\n"
"    <title>Index of %1$s</title>\n"
"    <style text=\"text/css\">\n"
"      body {\n"
"        background-color: white;\n"
"        color: black;\n"
"        font-family: sans-serif;\n"
"      }\n"
"      h1 {\n"
"        font-size: 150%%;\n"
"      }\n"
"      th {\n"
"        border-bottom: dashed 1px black;\n"
"      }\n"
"      td {\n"
"        padding: 0 1em 0 1em;\n"
"      }\n"
"      p.footer {\n"
"        color: #555;\n"
"        margin-top: 1em;\n"
"        padding-top: 0.2em;\n"
"        border-top: solid 1px #777;\n"
"        font-size: x-small;\n"
"      }\n"
"    </style>\n"
"  </head>\n"
"  <body>\n"
"    <h1>Index of %1$s</h1>\n"
"    <table>\n"
"      <tr> <th>Name</th> <th>Size</th> <th>Modified</th> </tr>\n",
		escurl);
	free(escurl);

	while ((de = readdir(dir)) != NULL) {
	struct direntry	ent;
	struct stat	sb;

		if (*de->d_name == '.')
			continue;

		if (fstatat(client->request->fd, de->d_name, &sb, 0) == -1) {
			client_error(client, "%s: stat: %s",
					de->d_name, strerror(errno));
			free(ent.name);
			continue;
		}

		bzero(&ent, sizeof(ent));
		ent.name = htmlescape(de->d_name);

		if (S_ISDIR(sb.st_mode))
			ent.isdir = 1;
		ent.size = sb.st_size;
		ent.mtime = sb.st_mtime;
		g_array_append_val(dirents, ent);
	}

	closedir(dir);
	dir = NULL;
	client->request->fd = -1;

	g_array_sort(dirents, dircmp);

	for (i = 0, end = dirents->len; i < end; ++i) {
	direntry_t	*ent = &g_array_index(dirents, direntry_t, i);
	char		*size = g_format_size_for_display(ent->size);
	char		 tbuf[64];
	struct tm	*tm;

		tm = localtime(&ent->mtime);
		strftime(tbuf, sizeof (tbuf), "%Y-%m-%d %H:%M", tm);
		client_printf(client, "      <tr> <td><a href=\"%1$s%2$s\">%1$s%2$s</a></td> "
				      "<td>%3$s</td> <td>%4$s</td> </tr>\n",
			ent->name, ent->isdir ? "/" : "", size, tbuf);
		free(ent->name);
	}

	g_array_free(dirents, TRUE);

	client_printf(client,
"    </table>\n"
"\n"
"  <p class=\"footer\">\n"
"    %s at %s\n"
"  </p>\n"
"\n"
"  </body>\n"
"</html>\n",
	server_version, client->request->vhost->name);

	client_drain(client, dir_write_done);
	return;

err:
	for (i = 0, end = dirents->len; i < end; ++i) {
	direntry_t	*ent = &g_array_index(dirents, direntry_t, i);
		free(ent->name);
	}

	g_array_free(dirents, TRUE);

	if (dir)
		closedir(dir);

	client_send_error(client, HTTP_INTERNAL_SERVER_ERROR);
}

void
handle_directory(client_t *client)
{
	if (client->request->method != M_GET) {
		client_send_error(client, HTTP_FORBIDDEN);
		return;
	}

	client->request->resp_status = xstrdup("200 OK");
	client_add_header(client, "Content-Type", "text/html");
	client_start_response(client, dir_start_write);
}

