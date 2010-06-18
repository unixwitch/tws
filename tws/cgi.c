/*
 * Copyright (c) 2010 River Tarnell.  All rights reserved.
 * Use is subject to license terms.
 */

#include	<unistd.h>
#include	<spawn.h>
#include	<stdio.h>
#include	<errno.h>
#include	<string.h>
#include	<stdlib.h>
#include	<pwd.h>
#include	<ctype.h>

#include	"cgi.h"
#include	"file.h"
#include	"log.h"
#include	"setup.h"
#include	"util.h"

static void cgi_read_callback(int, short, void *);
static void cgi_write_callback(int, short, void *);
static void client_write_callback(client_t *, int);
static void client_read_callback(int, short, void *);
static void setup_cgi_environment(client_t *, GPtrArray *);
static int spawn_cgi(
	const char *dir,
	const char *const *argp,
	const char *const *envp,
	int *fd_write,
	int *fd_read);

static void
add_env(
	GPtrArray	*env,
	const char	*key,
	const char	*value
)
{
char	*s;
	s = malloc(strlen(key) + strlen(value) + 2);
	sprintf(s, "%s=%s", key, value);
	g_ptr_array_add(env, s);
}

void
setup_cgi_environment(
	client_t *	 client,
	GPtrArray	*env
)
{
char		*tz = getenv("TZ");
GHashTableIter	 iter;
gpointer	 key, value;
request_t	*req = client->request;
char		*h;

	/* Missing:
	 * SERVER_ADMIN
	 * SERVER_PORT
	 */
	add_env(env, "PATH", "/bin:/usr/bin:/usr/local/bin");
	add_env(env, "GATEWAY_INTERFACE", "CGI/1.1");
	add_env(env, "SERVER_PROTOCOL",
		    req->version == HTTP_10 ? "HTTP/1.0" : "HTTP/1.1");
	add_env(env, "SCRIPT_FILENAME", req->filename);
	add_env(env, "REQUEST_METHOD", req->method_str);
	add_env(env, "REQUEST_URI", req->url);
	add_env(env, "QUERY_STRING", req->query ? req->query : "");
	add_env(env, "SCRIPT_NAME", req->url);
	add_env(env, "DOCUMENT_ROOT", req->vhost->docroot);
	add_env(env, "SERVER_NAME", req->vhost->name);
	add_env(env, "REMOTE_HOST", client->hostname);
	add_env(env, "REMOTE_ADDR", client->ip);
	add_env(env, "SERVER_SOFTWARE", server_version);

	if (req->pathinfo)
		add_env(env, "PATH_INFO", req->pathinfo);

	if (tz)
		add_env(env, "TZ", tz);

	g_hash_table_iter_init(&iter, req->headers);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
	char	*s, hdr[1024] = "HTTP_";

		strlcat(hdr, (char *) key, sizeof(hdr));
		for (s = hdr; *s; s++) {
			if (*s == '-')
				*s = '_';
			else if (islower(*s))
				*s = toupper(*s);
		}

		add_env(env, hdr, value);
	}

	if (req->post_length) {
	char	len[64];
		snprintf(len, sizeof (len), "%d", (int) req->post_length);
		add_env(env, "CONTENT_LENGTH", len);
	}

	if ((h = g_hash_table_lookup(req->headers, "Content-Type")) != NULL)
		add_env(env, "CONTENT_TYPE", h);

	g_ptr_array_add(env, NULL);
}

pid_t
spawn_cgi(
	const char 		*dir,
	const char *const 	*argv,
	const char *const 	*envp,
	int			*fd_write,
	int			*fd_read
)
{
posix_spawn_file_actions_t	fileactions;
pid_t	pid;
int	ret;
int	fds_write[2], fds_read[2];

	bzero(fds_write, sizeof(fds_write));
	bzero(fds_read, sizeof(fds_read));

	if (fd_write) {
		if (socketpair(PF_UNIX, SOCK_STREAM, 0, fds_write) == -1) {
			log_error("spawn_cgi: pipe: %s", strerror(errno));
			goto err;
		}
		*fd_write = fds_write[1];
	}

	if (fd_read) {
		if (socketpair(PF_UNIX, SOCK_STREAM, 0, fds_read) == -1) {
			log_error("spawn_cgi: pipe: %s", strerror(errno));
			goto err;
		}
		*fd_read = fds_read[0];
	}

	/* need to chdir to the docroot */
	if (dir && chdir(dir) == -1) {
		log_error("spawn_cgi: chdir(%s): %s",
			dir, strerror(errno));
		goto err;
	}

	posix_spawn_file_actions_init(&fileactions);

	if (fd_read) {
		posix_spawn_file_actions_addclose(&fileactions, fds_read[0]);
		posix_spawn_file_actions_adddup2(&fileactions, fds_read[1], STDOUT_FILENO);
		posix_spawn_file_actions_addclose(&fileactions, fds_read[1]);
	}

	if (fd_write) {
		posix_spawn_file_actions_addclose(&fileactions, fds_write[1]);
		posix_spawn_file_actions_adddup2(&fileactions, fds_write[0], STDIN_FILENO);
		posix_spawn_file_actions_addclose(&fileactions, fds_write[0]);
	}

	ret = posix_spawn(&pid, argv[0], &fileactions, NULL,
		(char *const *)argv, 
		(char *const *)envp);
	posix_spawn_file_actions_destroy(&fileactions);

	if (fds_write[0])
		close(fds_write[0]);
	if (fds_read[1])
		close(fds_read[1]);
	fds_write[0] = fds_read[1] = 0;

	if (dir && chdir("/") == -1) {
		log_error("chdir(/): %s", strerror(errno));
		_exit(1);
	}

	if (ret == -1)
		goto err;
	return 0;

err:
	if (fds_read[1])
		close(fds_read[1]);
	if (fds_write[0])
		close(fds_write[0]);
	return -1;
}

void
handle_cgi_request(client_t *client)
{
int		 ret;
char		 gid[32];
char		 un[64];
GPtrArray	*argv, *envp;
char		 s[1024];
guint		 i;
const char	*dir = NULL;
char		 dirs[1024];
request_t	*req = client->request;
char		*execname = NULL;
interp_t	*ip;

	if (req->method == M_POST) {
	char	*len;
		if ((len = g_hash_table_lookup(req->headers, "Content-Length")) == NULL) {
			client_send_error(client, HTTP_LENGTH_REQUIRED);
			return;
		}

		req->post_length = atoi(len);
	}

	req->cgi_state = CGI_READ_HEADERS;

	/* See if this is an interpreter request */
	if ((ip = g_hash_table_lookup(req->vhost->interps, req->mimetype)) != NULL)
		execname = ip->path;

	argv = g_ptr_array_new();
	envp = g_ptr_array_new_with_free_func(free);

	/* Set up argv */
	if (!req->vhost->suexec_enable || !req->flags.userdir) {
		if (execname)
			g_ptr_array_add(argv, execname);

		g_ptr_array_add(argv, req->filename);
		g_ptr_array_add(argv, NULL);
	} else if (req->vhost->suexec_enable) {
	struct passwd	*pwd;
		if ((pwd = getpwnam(req->username)) == NULL) {
			log_error("handle_cgi_request: %s: unknown user",
				req->username);
			goto err;
		}

		snprintf(gid, sizeof (gid), "%d", (int) pwd->pw_gid);
		snprintf(un, sizeof (un), "%s%s",
			req->flags.userdir ? "~" : "", req->username);

		g_ptr_array_add(argv, execname ? SUEXEC_WEAK : SUEXEC);
		g_ptr_array_add(argv, execname ? req->username : un);
		g_ptr_array_add(argv, gid);
		if (execname)
			g_ptr_array_add(argv, execname);
		g_ptr_array_add(argv, req->urlname);
		g_ptr_array_add(argv, NULL);

		/* suexec requires us to chdir to the document root */
		if (req->flags.userdir)
			snprintf(dirs, sizeof (dirs), "%s/%s", 
				pwd->pw_dir, req->vhost->userdir);
		else
			strlcpy(dirs, req->vhost->docroot, sizeof(dirs));
		dir = dirs;
	}

	setup_cgi_environment(client, envp);

	ret = spawn_cgi(dir, 
		(const char *const *) argv->pdata, 
		(const char *const *) envp->pdata,
		req->post_length ? &req->fd_write : NULL,
		&req->fd_read);

	if (ret == -1) {
		log_error("handle_cgi_request: %s: spawn_cgi: %s",
				req->filename, strerror(errno));
		goto err;
	}

	g_ptr_array_free(envp, TRUE);
	g_ptr_array_free(argv, TRUE);

	if ((req->cgi_buffer = evbuffer_new()) == NULL)
		outofmemory();
	req->cgi_headers = g_hash_table_new_full(g_str_hash, g_str_equal, free, NULL);

	if  (req->post_length) {
		event_set(&client->ev, client->fd, EV_READ,
				client_read_callback, client);
		event_add(&client->ev, &curconf->timeout);
	} else {
		event_set(&req->ev, req->fd_read, EV_READ,
				cgi_read_callback, client);
		event_add(&req->ev, NULL);
	}

	return;

err:
	if (envp)
		g_ptr_array_free(envp, TRUE);
	if (argv)
		g_ptr_array_free(argv, TRUE);
	client_send_error(client, HTTP_INTERNAL_SERVER_ERROR);
}

static void
cgi_read_callback(
	int	fd,
	short	what,
	void	*arg
)
{
char		 buf[4096];
ssize_t		 i;
client_t	*client = arg;
char		*line, *s;
GHashTableIter	 iter;
char		*header, *value;
int		 ret;

	/*
	 * If we're reading the body, just pass it through.
	 */
	if (client->request->cgi_state == CGI_READ_BODY) {
		i = read(client->request->fd_read, buf, sizeof (buf));

		if (i == 0) {
			client_close(client);
			return;
		}

		if (i == -1 && errno == EAGAIN) {
			event_add(&client->request->ev, NULL);
			return;
		}

		if (i == -1) {
			client_error(client, "CGI read: %s", strerror(errno));
			client_abort(client);
			return;
		}

		client_write(client, buf, i);
		client_drain(client, client_write_callback);
		return;
	}

	/*
	 * We're reading headers.  Buffer all headers until the empty line
	 * signifying the start of the body.
	 */
	if ((ret = evbuffer_read(client->request->cgi_buffer,
	    client->request->fd_read, READ_BUFSZ)) == -1) {
		if (errno == EAGAIN) {
			event_add(&client->request->ev, NULL);
			return;
		}

		client_error(client, "CGI read: %s", strerror(errno));
		client_send_error(client, HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

	if (ret == 0) {
		client_error(client, "EOF reading CGI response headers");
		client_send_error(client, HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

	/*
	 * Keep reading if we haven't read the entire header yet
	 */
	if (evbuffer_find(client->request->cgi_buffer, (const u_char *) "\n\n", 2) == NULL &&
	    evbuffer_find(client->request->cgi_buffer, (const u_char *) "\n\r\n", 3) == NULL) {
		event_add(&client->request->ev, NULL);
		return;
	}

	while ((line = evbuffer_readline(client->request->cgi_buffer)) != NULL) {
		if (!*line)
			break;

		header = line;
		if ((value = strstr(line, ": ")) == NULL) {
			client_error(client, "CGI read: invalid header: %s", header);
			client_send_error(client, HTTP_INTERNAL_SERVER_ERROR);
			return;
		}
		*value = '\0';
		value += 2;

		/*
		 * Don't let CGIs set certain headers which would confuse
		 * the client.
		 */
		if (!strcmp(header, "Connection") ||
		    !strcmp(header, "Transfer-Encoding"))
			continue;

		g_hash_table_replace(client->request->cgi_headers,
				header, value);
	}

	/*
	 * If the client set a status, use that, otherwise set our own.
	 */
	if ((s = g_hash_table_lookup(client->request->cgi_headers, "Status")) != NULL) {
		client->request->resp_status = xstrdup(s);
		g_hash_table_remove(client->request->cgi_headers, "Status");
	} else
		client->request->resp_status = xstrdup("200 OK");

	/* Add all remaining headers */
	g_hash_table_iter_init(&iter, client->request->cgi_headers);
	while (g_hash_table_iter_next(&iter, (gpointer *) &header, (gpointer *) &value))
		client_add_header(client, header, value);
	
	client->request->cgi_state = CGI_READ_BODY;
	client_start_response(client, client_write_callback);

	evbuffer_add_buffer(client->wrbuf, client->request->cgi_buffer);
}


void
client_write_callback(
	client_t	*client,
	int		 error
)
{
	if (error) {
		client_error(client, "CGI write: %s", strerror(errno));
		client_abort(client);
		return;
	}

	event_add(&client->request->ev, NULL);
}

void
client_read_callback(
	int	fd,
	short	what,
	void	*arg
)
{
client_t	*client = arg;
request_t	*req = client->request;
static char	 rdbuf[1024 * 256];
ssize_t		 ret;
ssize_t		 maxrd;

	maxrd = sizeof (rdbuf) > req->post_length ? req->post_length : sizeof (rdbuf);
	ret = read(fd, rdbuf, maxrd);
	
	if (ret == -1 && errno == EAGAIN) {
		event_add(&client->ev, &curconf->timeout);
		return;
	}

	if (ret == -1 || ret == 0) {
		client_abort(client);
		return;
	}

	req->post_length -= ret;
	evbuffer_add(req->cgi_write_buffer, rdbuf, ret);
	event_set(&req->ev, req->fd_write, EV_WRITE, cgi_write_callback, client);
	event_add(&req->ev, NULL);
}

void
cgi_write_callback(
	int	fd,
	short	what,
	void	*arg
)
{
client_t	*client = arg;
request_t	*req = client->request;
int		 ret;

	while ((ret = evbuffer_write(req->cgi_write_buffer, req->fd_write)) > 0)
		;

	if (ret == -1 && errno == EAGAIN) {
		event_add(&client->request->ev, NULL);
		return;
	}

	if (ret == -1) {
		client_error(client, "CGI write: %s", strerror(errno));
		client_send_error(client, HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

	/* Buffer drained */
	if (req->post_length) {
		event_add(&client->ev, &curconf->timeout);
		return;
	}

	/* No more data, switch to reading the CGI response */
	close(req->fd_write);
	req->fd_write = 0;
	event_set(&req->ev, req->fd_read, EV_READ,
			cgi_read_callback, client);
	event_add(&req->ev, NULL);
}

