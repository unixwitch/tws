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

static void cgi_read_callback(int, short, void *);
static void client_write_callback(client_t *, int);
static void free_request(file_request_t *req);
static int setup_cgi_environment(client_t *, file_request_t *, GPtrArray *);
static int spawn_cgi(
	const char *dir,
	const char *const *argp,
	const char *const *envp,
	int fds[2]);

static int
add_env(
	GPtrArray	*env,
	const char	*key,
	const char	*value
)
{
char	*s;
	if ((s = malloc(strlen(key) + strlen(value) + 2)) == NULL)
		return -1;
	sprintf(s, "%s=%s", key, value);
	g_ptr_array_add(env, s);
	return 0;
}

int
setup_cgi_environment(
	client_t *	 client,
	file_request_t	*req,
	GPtrArray	*env
)
{
char		*tz = getenv("TZ");
GHashTableIter	 iter;
gpointer	 key, value;

	/* Missing:
	 * SERVER_ADMIN
	 * SERVER_PORT
	 * SERVER_SOFTWARE
	 * REMOTE_HOST
	 * REMOTE_ADDR
	 */
	if (add_env(env, "PATH", "/bin:/usr/bin:/usr/local/bin") == -1 ||
	    add_env(env, "GATEWAY_INTERFACE", "CGI/1.1") == -1 ||
	    add_env(env, "SERVER_PROTOCOL",
		    client->request->version == HTTP_10 ? "HTTP/1.0" : "HTTP/1.1") == -1 ||
	    add_env(env, "SCRIPT_FILENAME", req->filename) == -1 ||
	    add_env(env, "REQUEST_METHOD", client->request->method) == -1 ||
	    add_env(env, "REQUEST_URI", client->request->url) == -1 ||
	    add_env(env, "QUERY_STRING", req->query ? req->query : "") == -1 ||
	    add_env(env, "SCRIPT_NAME", client->request->url) == -1 ||
	    add_env(env, "DOCUMENT_ROOT", req->vhost->docroot) == -1 ||
	    add_env(env, "SERVER_NAME", req->vhost->name) == -1) {
		goto err;
	}

	if (tz)
		if (add_env(env, "TZ", tz) == -1)
			goto err;

	g_hash_table_iter_init(&iter, client->request->headers);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
	char	*s, hdr[1024] = "HTTP_";

		strlcat(hdr, (char *) key, sizeof(hdr));
		for (s = hdr; *s; s++) {
			if (*s == '-')
				*s = '_';
			else if (islower(*s))
				*s = toupper(*s);
		}

		if (add_env(env, hdr, value) == -1)
			goto err;
	}

	return 0;

err:
	return -1;
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
handle_cgi_request(
	client_t	*client,
	file_request_t	*req
)
{
int		 ret;
char		 gid[32];
char		 un[64];
GPtrArray	*argv, *envp;
char		 s[1024];
guint		 i;
const char	*dir;
char		 dirs[1024];

	req->fds[0] = req->fds[1] = -1;

	if (pipe(req->fds) == -1) {
		log_error("spawn_cgi: pipe: %s", strerror(errno));
		goto err;
	}

	if ((argv = g_ptr_array_new()) == NULL) {
		log_error("handle_cgi_request: %s",
			strerror(errno));
		goto err;
	}

	if ((envp = g_ptr_array_new_with_free_func(free)) == NULL) {
		log_error("handle_cgi_request: %s",
			strerror(errno));
		goto err;
	}

	/* Set up argv */
	if (!req->vhost->suexec_enable) {
		g_ptr_array_add(argv, req->filename);
		g_ptr_array_add(argv, NULL);
	} else if (req->vhost->suexec_enable) {
	struct passwd	*pwd;
		if ((pwd = getpwnam(req->username)) == NULL) {
			log_error("handle_cgi_request: %s: unknown user",
				req->username);
			goto err;
		}

		printf("suexec urlname=[%s]\n", req->urlname);

		snprintf(gid, sizeof (gid), "%d", (int) pwd->pw_gid);
		snprintf(un, sizeof (un), "%s%s",
			req->userdir ? "~" : "", req->username);

		g_ptr_array_add(argv, SUEXEC);
		g_ptr_array_add(argv, un);
		g_ptr_array_add(argv, gid);
		g_ptr_array_add(argv, req->urlname);
		g_ptr_array_add(argv, NULL);

		/* suexec requires us to chdir to the document root */
		if (req->userdir)
			snprintf(dirs, sizeof (dirs), "%s/%s", 
				pwd->pw_dir, req->vhost->userdir);
		else
			strlcpy(dirs, req->vhost->docroot, sizeof(dirs));
		dir = dirs;
	}

	if (setup_cgi_environment(client, req, envp) == -1) {
		log_error("handle_cgi_request: setup_cgi_environment: %s",
			strerror(errno));
		goto err;
	}

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
	g_ptr_array_free(envp, TRUE);
	g_ptr_array_free(argv, TRUE);

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
	client_error(client, 500);
	free_request(req);
}

static void
cgi_read_callback(
	int	fd,
	short	what,
	void	*arg
)
{
char	buf[4096];
ssize_t	i;
client_t	*client = arg;
file_request_t	*freq = client->hdldata;

	i = read(freq->fds[0], buf, sizeof (buf));

	if (i == 0) {
		client_close(client);
		free_request(freq);
		return;
	}

	if (i == -1 && errno == EAGAIN) {
		event_add(&freq->ev, NULL);
		return;
	}

	if (i == -1) {
		log_error("%s: read: %s",
				freq->filename,
				strerror(errno));
		client_close(client);
		free_request(freq);
		return;
	}

	evbuffer_add(client->wrbuf, buf, i);
	client_drain(client, client_write_callback);
}

void
client_write_callback(
	client_t	*client,
	int		 error
)
{
file_request_t	*req = client->hdldata;

	if (error) {
		log_error("client_write_callback: %s",
			strerror(errno));
		client_close(client);
		free_request(req);
		return;
	}

	event_add(&req->ev, NULL);
}

void
free_request(
	file_request_t	*req
)
{
	if (!req)
		return;

	free(req->filename);
	free(req->pathinfo);
	free(req->urlname);
	close(req->fds[0]);
	free(req);
}
