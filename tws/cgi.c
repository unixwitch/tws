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
static void client_write_callback(client_t *, int);
static void cgi_last_chunk_done(client_t *, int);
static void setup_cgi_environment(client_t *, GPtrArray *);
static int spawn_cgi(
	const char *dir,
	const char *const *argp,
	const char *const *envp,
	int fds[2]);

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

	/* Missing:
	 * SERVER_ADMIN
	 * SERVER_PORT
	 * SERVER_SOFTWARE
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

	g_ptr_array_add(env, NULL);
}

pid_t
spawn_cgi(
	const char *dir,
	const char *const *argv,
	const char *const *envp,
	int fds[2]
)
{
posix_spawn_file_actions_t	fileactions;
pid_t	pid;
int	ret;

	/* need to chdir to the docroot */
	if (dir && chdir(dir) == -1)
		return -1;

	posix_spawn_file_actions_init(&fileactions);
	posix_spawn_file_actions_addclose(&fileactions, fds[0]);
	posix_spawn_file_actions_adddup2(&fileactions, fds[1], STDOUT_FILENO);
	posix_spawn_file_actions_addclose(&fileactions, fds[1]);

	ret = posix_spawn(&pid, argv[0], &fileactions, NULL,
		(char *const *)argv, 
		(char *const *)envp);
	posix_spawn_file_actions_destroy(&fileactions);

	if (dir && chdir("/") == -1) {
		log_error("chdir(/): %s", strerror(errno));
		_exit(1);
	}

	return ret == 0 ? pid : -1;
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

	req->cgi_state = CGI_READ_HEADERS;

	if (pipe(req->fds) == -1) {
		log_error("spawn_cgi: pipe: %s", strerror(errno));
		goto err;
	}

	argv = g_ptr_array_new();

	envp = g_ptr_array_new_with_free_func(free);

	/* Set up argv */
	if (!req->vhost->suexec_enable || !req->flags.userdir) {
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

		g_ptr_array_add(argv, SUEXEC);
		g_ptr_array_add(argv, un);
		g_ptr_array_add(argv, gid);
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
		req->fds);

	if (ret == -1) {
		log_error("handle_cgi_request: %s: spawn_cgi: %s",
				req->filename, strerror(errno));
		goto err;
	}

	close(req->fds[1]);
	req->fds[1] = -1;

	g_ptr_array_free(envp, TRUE);
	g_ptr_array_free(argv, TRUE);

	if ((req->cgi_buffer = evbuffer_new()) == NULL)
		outofmemory();
	req->cgi_headers = g_hash_table_new_full(g_str_hash, g_str_equal, free, NULL);

	event_set(&req->ev, req->fds[0], EV_READ,
			cgi_read_callback, client);
	event_add(&req->ev, NULL);
	return;

err:
	if (envp)
		g_ptr_array_free(envp, TRUE);
	if (argv)
		g_ptr_array_free(argv, TRUE);
	if (req->fds[0] != -1)
		close(req->fds[0]);
	if (req->fds[1] != -1)
		close(req->fds[1]);
	client_send_error(client, 500);
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
char		*line;
GHashTableIter	 iter;
char		*header, *value;
int		 ret;

	/*
	 * If we're reading the body, just pass it through.
	 */
	if (client->request->cgi_state == CGI_READ_BODY) {
		i = read(client->request->fds[0], buf, sizeof (buf));

		if (i == 0) {
			/*
			 * If we're not using chunked TE, and there was no
			 * content-length in the CGI response, we can't
			 * do keepalive here, so abort the client when
			 * we're done writing.
			 */
			if (!client->request->flags.write_chunked &&
			    !client->request->flags.cgi_had_cl) {
				client_abort(client);
				return;
			}

			evbuffer_add_printf(client->wrbuf, "0\r\n");
			client_drain(client, cgi_last_chunk_done);
			return;
		}

		if (i == -1 && errno == EAGAIN) {
			event_add(&client->request->ev, NULL);
			return;
		}

		if (i == -1) {
			log_error("%s: read: %s",
					client->request->filename,
					strerror(errno));
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
	    client->request->fds[0], READ_BUFSZ)) == -1) {
		if (errno == EAGAIN) {
			event_add(&client->request->ev, NULL);
			return;
		}

		client_error(client, "CGI read: %s", strerror(errno));
		client_send_error(client, 500);
		return;
	}

	if (ret == 0) {
		client_error(client, "EOF reading CGI response headers");
		client_send_error(client, 500);
		return;
	}

	/*
	 * Keep reading if we haven't read the entire header yet
	 */
	if (evbuffer_find(client->request->cgi_buffer, "\n\n", 2) == NULL &&
	    evbuffer_find(client->request->cgi_buffer, "\n\r\n", 3) == NULL) {
		event_add(&client->request->ev, NULL);
		return;
	}

	while ((line = evbuffer_readline(client->request->cgi_buffer)) != NULL) {
		if (!*line)
			break;

		header = line;
		if ((value = strstr(line, ": ")) == NULL) {
			client_error(client, "CGI read: invalid header: %s", header);
			client_send_error(client, 500);
			return;
		}
		*value++ = '\0';

		g_hash_table_replace(client->request->cgi_headers,
				header, value);
	}

	if ((client->request->cgi_status = g_hash_table_lookup(
	    client->request->cgi_headers, "Status")) == NULL)
		client->request->cgi_status = "200 OK";
	else
		g_hash_table_remove(client->request->cgi_headers,
				"Status");

	evbuffer_add_printf(client->wrbuf, "HTTP/1.1 %s\r\n",
			client->request->cgi_status);

	g_hash_table_iter_init(&iter, client->request->cgi_headers);
	while (g_hash_table_iter_next(&iter, (gpointer *) &header, (gpointer *) &value))
		evbuffer_add_printf(client->wrbuf, "%s: %s\r\n",
			header, value);
	if (g_hash_table_lookup(client->request->cgi_headers, "Server") == NULL)
		evbuffer_add_printf(client->wrbuf, "Server: %s\r\n",
				server_version);
	if (g_hash_table_lookup(client->request->cgi_headers, "Date") == NULL)
		evbuffer_add_printf(client->wrbuf, "Date: %s\r\n", current_time);
	
	if (g_hash_table_lookup(client->request->cgi_headers, "Content-Length") == NULL) {
		client->request->flags.cgi_had_cl = 0;
		
		if (client->request->flags.accept_chunked) {
			evbuffer_add_printf(client->wrbuf,
				"Transfer-Encoding: chunked\r\n");
			client->request->flags.write_chunked = 1;
		}
	}

	evbuffer_add_printf(client->wrbuf, "\r\n");

	client->request->cgi_state = CGI_READ_BODY;
	client_drain(client, client_write_callback);
}


void
client_write_callback(
	client_t	*client,
	int		 error
)
{
	if (error) {
		log_error("client_write_callback: %s",
			strerror(errno));
		client_abort(client);
		return;
	}

	event_add(&client->request->ev, NULL);
}

void
cgi_last_chunk_done(
	client_t	*client,
	int		 error
)
{
	if (error) {
		log_error("client_write_callback: %s",
			strerror(errno));
		client_abort(client);
		return;
	}

	client_close(client);
}
