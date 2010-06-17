/*
 * Copyright (c) 2010 River Tarnell.  All rights reserved.
 * Use is subject to license terms.
 */

#include	<sys/socket.h>
#include	<stdio.h>
#include	<errno.h>
#include	<string.h>
#include	<stdlib.h>
#include	<ctype.h>

#include	<confuse.h>

#include	"config.h"
#include	"util.h"

static int
verify_protocol(cfg, opt, value, result)
	cfg_t		*cfg;
	cfg_opt_t	*opt;
	char const	*value;
	void		*result;
{
	(void) opt;

	if (strcmp(value, "ipv4") == 0)
		*(long int *) result = AF_INET;
	else if (strcmp(value, "ipv6") == 0)
		*(long int *) result = AF_INET6;
	else if (strcmp(value, "any") == 0)
		*(long int *) result = 0;
	else {
		cfg_error(cfg, "unknown protocol \"%s\" (expected \"ipv4\", \"ipv6\" or \"any\")",
				value);
		return -1;
	}

	return 0;
}

static int
verify_interp_protocol(cfg, opt, value, result)
	cfg_t		*cfg;
	cfg_opt_t	*opt;
	char const	*value;
	void		*result;
{
	(void) opt;

	if (strcmp(value, "cgi") == 0)
		*(long int *) result = PR_CGI;
	else if (strcmp(value, "fastcgi") == 0)
		*(long int *) result = PR_FASTCGI;
	else {
		cfg_error(cfg, "unknown protocol \"%s\" (expected \"cgi\" or \"fastcgi\")",
				value);
		return -1;
	}

	return 0;
}

static cfg_opt_t interpreter_opts[] = {
	CFG_STR_LIST("mime-types", "{}", CFGF_NONE),
	CFG_INT_CB("protocol", PR_CGI, CFGF_NONE, &verify_interp_protocol),
	CFG_END()
};

static cfg_opt_t cgi_opts[] = {
	CFG_STR_LIST("mime-types", "{}", CFGF_NONE),
	CFG_STR_LIST("cgi-bin", "{}", CFGF_NONE),
	CFG_END()
};

static cfg_opt_t suexec_opts[] = {
	CFG_BOOL("enable", 0, CFGF_NONE),
	CFG_END()
};

static cfg_opt_t userdir_opts[] = {
	CFG_STR("prefix", 0, CFGF_NONE),
	CFG_STR("dir", 0, CFGF_NONE),
	CFG_END()
};

static cfg_opt_t vhost_opts[] = {
	CFG_STR("docroot", 0, CFGF_NONE),
	CFG_SEC("userdir", userdir_opts, CFGF_NONE),
	CFG_SEC("cgi", cgi_opts, CFGF_NONE),
	CFG_SEC("suexec", suexec_opts, CFGF_NONE),
	CFG_SEC("interpreter", interpreter_opts, CFGF_TITLE | CFGF_MULTI),
	CFG_STR_LIST("aliases", "{}", CFGF_NONE),
	CFG_STR_LIST("index-file", "{}", CFGF_NONE),
	CFG_STR("default-content-type", 0, CFGF_NONE),
	CFG_END()
};

static cfg_opt_t listen_opts[] = {
	CFG_INT("backlog", 64, CFGF_NONE),
	CFG_INT_CB("protocol", 0, CFGF_NONE, &verify_protocol),
	CFG_END()
};

static cfg_opt_t opts[] = {
	CFG_INT("timeout", 120, CFGF_NONE),
	CFG_SEC("virtualhost", vhost_opts, CFGF_MULTI | CFGF_TITLE),
	CFG_SEC("listen", listen_opts, CFGF_MULTI | CFGF_TITLE),
	CFG_STR("user", 0, CFGF_NONE),
	CFG_STR("group", 0, CFGF_NONE),
	CFG_STR_LIST("index-file", "{}", CFGF_NONE),
	CFG_BOOL("resolve-hostnames", 0, CFGF_NONE),
	CFG_INT("compression-level", 6, CFGF_NONE),
	CFG_STR_LIST("compress-types", "{}", CFGF_NONE),
	CFG_BOOL("compress-cgi", 0, CFGF_NONE),
	CFG_INT("max-clients", 10000, CFGF_NONE),
	CFG_INT("nfiles", 0, CFGF_NONE),
	CFG_BOOL("use-sendfile", 
#ifdef __FreeBSD__
			cfg_true,
#else
			cfg_false,
#endif
			CFGF_NONE),
	CFG_STR("default-content-type", 0, CFGF_NONE),
	CFG_STR("mime-type-file", 0, CFGF_NONE),
	CFG_FUNC("include", cfg_include),
	CFG_END()
};

static tws_config_t *
config_alloc(void)
{
tws_config_t	*cfg = NULL;
	if ((cfg = calloc(1, sizeof(*cfg))) == NULL)
		goto err;

	if ((cfg->listeners = g_ptr_array_new()) == NULL)
		goto err;
	if ((cfg->vhosts = g_ptr_array_new()) == NULL)
		goto err;
	return cfg;

err:
	free(cfg);
	return NULL;
}

static tws_listen_t *
parse_listen(cfg)
	cfg_t	*cfg;
{
tws_listen_t	*ls = NULL;

	ls = xcalloc(1, sizeof (*ls));
	ls->addr = xstrdup(cfg_title(cfg));

	if ((ls->port = strchr(ls->addr, ':')) != NULL)
		*ls->port++ = '\0';

	ls->backlog = cfg_getint(cfg, "backlog");
	ls->protocol = cfg_getint(cfg, "protocol");

	return ls;
}

static vhost_t *
parse_vhost(cfg)
	cfg_t	*cfg;
{
vhost_t		*vh = NULL;
cfg_t		*scfg;
char		*s;
int		 i, j;

	vh = xcalloc(1, sizeof (*vh));
	vh->name = xstrdup(cfg_title(cfg));

	if ((s = cfg_getstr(cfg, "docroot")) == NULL) {
		cfg_error(cfg, "virtualhost \"%s\": no docroot specified", vh->name);
		goto err;
	}

	vh->docroot = xstrdup(s);

	if ((s = cfg_getstr(cfg, "default-content-type")) != NULL)
		vh->deftype = xstrdup(s);

	vh->aliases = g_ptr_array_new_with_free_func(free);
	vh->indexes = g_ptr_array_new_with_free_func(free);

	for (i = 0, j = cfg_size(cfg, "index-file"); i < j; i++)
		g_ptr_array_add(
			vh->indexes, 
			xstrdup(cfg_getnstr(cfg, "index-file", i)));

	if ((scfg = cfg_getsec(cfg, "userdir")) != NULL) {
	char	*s;

		if ((s = cfg_getstr(scfg, "prefix")) == NULL) {
			cfg_error(scfg, "userdir prefix must be specified");
			goto err;
		}
		vh->userdir_prefix = xstrdup(s);

		if ((s = cfg_getstr(scfg, "dir")) == NULL) {
			cfg_error(scfg, "userdir directory must be specified");
			goto err;
		}
		vh->userdir = xstrdup(s);
	}

	vh->cgitypes = g_hash_table_new_full(
			g_str_hash, g_str_equal,
			free, NULL);

	vh->cgidirs = g_hash_table_new_full(
			g_str_hash, g_str_equal,
			free, NULL);

	if ((scfg = cfg_getsec(cfg, "cgi")) != NULL) {
	char	*s;
	int	 i, end;

		for (i = 0, end = cfg_size(scfg, "mime-types"); i < end; i++) {
			s = xstrdup(cfg_getnstr(scfg, "mime-types", i));
			g_hash_table_replace(vh->cgitypes, s, NULL);
		}

		for (i = 0, end = cfg_size(scfg, "cgi-bin"); i < end; i++) {
			s = xstrdup(cfg_getnstr(scfg, "cgi-bin", i));
			g_hash_table_replace(vh->cgidirs, s, NULL);
		}
	}

	vh->interps = g_hash_table_new_full(
		g_str_hash, g_str_equal, free, free);

	for (i = 0, j = cfg_size(cfg, "interpreter"); i < j; ++i) {
	cfg_t		*ipc = cfg_getnsec(cfg, "interpreter", i);
	int		 i, end;

		for (i = 0, end = cfg_size(ipc, "mime-types"); i < end; i++) {
		interp_t	*ip;
		const char	*path;

			path = cfg_title(ipc);
			ip = xcalloc(1, sizeof(*ip) + strlen(path) + 1);
			ip->path = (char *) ip + sizeof(*ip);
			strcpy(ip->path, path);

			g_hash_table_replace(
				vh->interps,
				xstrdup(cfg_getnstr(ipc, "mime-types", i)),
				ip);
		}
	}
	
	if ((scfg = cfg_getsec(cfg, "suexec")) != NULL) {
		if (cfg_getbool(scfg, "enable"))
			vh->suexec_enable = 1;
	}

	return vh;

err:
	if (vh) {
		free(vh->name);
		free(vh->docroot);
	}
	free(vh);
	return NULL;
}

tws_config_t *
config_load(filename)
	const char	*filename;
{
cfg_t		*cfg = NULL;
tws_config_t	*tcfg = NULL;
int		 i, j;
char		*s;

	cfg = cfg_init(opts, CFGF_NONE);

	switch (cfg_parse(cfg, filename)) {
	case CFG_FILE_ERROR:
		(void) fprintf(stderr, "%s: %s\n",
				filename, strerror(errno));
		goto err;

	case CFG_PARSE_ERROR:
		(void) fprintf(stderr, "%s: parse error\n",
				filename);
		goto err;

	default:
		break;
	}

	if ((tcfg = config_alloc()) == NULL)
		goto err;

	/* Set global options */
	tcfg->timeout = cfg_getint(cfg, "timeout");
	if ((s = cfg_getstr(cfg, "user")) != NULL)
		tcfg->user = strdup(s);
	if ((s = cfg_getstr(cfg, "group")) != NULL)
		tcfg->group = strdup(s);

	if ((s = cfg_getstr(cfg, "default-content-type")) != NULL) {
		if ((tcfg->deftype = strdup(s)) == NULL)
			goto err;
	}

	tcfg->dodns = cfg_getbool(cfg, "resolve-hostnames");
	tcfg->compr_level = cfg_getint(cfg, "compression-level");
	tcfg->compr_cgi = cfg_getbool(cfg, "compress-cgi");
	tcfg->compr_types = g_ptr_array_new_with_free_func(free);
	tcfg->nfiles = cfg_getint(cfg, "nfiles");
	tcfg->maxclients = cfg_getint(cfg, "max-clients");

	for (i = 0, j = cfg_size(cfg, "compress-types"); i < j; i++)
		g_ptr_array_add(
			tcfg->compr_types,
			xstrdup(cfg_getnstr(cfg, "compress-types", i)));

	tcfg->indexes = g_ptr_array_new_with_free_func(free);

	for (i = 0, j = cfg_size(cfg, "index-file"); i < j; i++)
		g_ptr_array_add(
			tcfg->indexes, 
			xstrdup(cfg_getnstr(cfg, "index-file", i)));

	tcfg->mimetypes = g_hash_table_new_full(
			g_str_hash, g_str_equal,
			free, NULL);

	if ((s = cfg_getstr(cfg, "mime-type-file")) != NULL) {
	FILE	*f;
	char	 buf[1024];

		if ((f = fopen(s, "r")) == NULL) {
			(void) fprintf(stderr, "%s: %s\n",
				s, strerror(errno));
			goto err;
		}

		while (fgets(buf, sizeof (buf), f)) {
		char	*ext = buf, *type;

			if (!*buf)
				continue;

			if (buf[strlen(buf) - 1] == '\n')
				buf[strlen(buf) - 1] = '\0';

			while (isspace(*ext))
				ext++;

			if (!*ext)
				continue;

			if ((ext = strdup(ext)) == NULL) {
				(void) fprintf(stderr,
					"%s: %s\n", s,
					strerror(errno));
				goto err;
			}

			if ((type = strchr(ext, ' ')) == NULL) {
				(void) fprintf(stderr,
					"%s: malformed line: %s\n",
					s, buf);
				goto err;
			}
			*type++ = '\0';

			g_hash_table_replace(tcfg->mimetypes,
				ext, type);
		}

		fclose(f);
	}

#ifdef __FreeBSD__
	tcfg->use_sendfile = cfg_getbool(cfg, "use-sendfile");
#else
	if (cfg_getbool(cfg, "use-sendfile")) {
		(void) fprintf(stderr, "%s: use-sendfile is not supported "
				"on this platform\n", filename);
		goto err;
	}
#endif

	/* Listen blocks */
	for (i = 0, j = cfg_size(cfg, "listen"); i < j; ++i) {
	tws_listen_t	 *ls;
		if ((ls = parse_listen(cfg_getnsec(cfg, "listen", i))) == NULL)
			goto err;
		g_ptr_array_add(tcfg->listeners, ls);
	}

	/* Virtual host blocks */
	for (i = 0, j = cfg_size(cfg, "virtualhost"); i < j; ++i) {
	vhost_t		*vh;
		if ((vh = parse_vhost(cfg_getnsec(cfg, "virtualhost", i))) == NULL)
			goto err;
		g_ptr_array_add(tcfg->vhosts, vh);
	}

	return tcfg;

err:
	if (cfg)
		cfg_free(cfg);
	if (tcfg)
		config_free(tcfg);
	return NULL;
}

void
config_free(cfg)
	tws_config_t	*cfg;
{
guint	i, j;

	if (!cfg)
		return;

	free(cfg->user);
	free(cfg->group);
	free(cfg->deftype);

	g_hash_table_destroy(cfg->mimetypes);

	for (i = 0; i < cfg->vhosts->len; ++i) {
	vhost_t	*vh = g_ptr_array_index(cfg->vhosts, i);
		free(vh->name);
		free(vh->docroot);
		free(vh->cgidirs);
		free(vh->cgitypes);
		g_ptr_array_free(vh->aliases, TRUE);
	}
	g_ptr_array_free(cfg->vhosts, TRUE);

	for (i = 0; i < cfg->listeners->len; ++i) {
	tws_listen_t	*ls = g_ptr_array_index(cfg->vhosts, i);
		free(ls->addr);
		free(ls->port);
	}
	g_ptr_array_free(cfg->listeners, TRUE);

	free(cfg);
}

vhost_t *
config_find_vhost(
	const char *name
)
{
guint	i;
	for (i = 0; i < curconf->vhosts->len; ++i) {
	vhost_t	*vh = g_ptr_array_index(curconf->vhosts, i);
		if (!strcasecmp(name, vh->name))
			return vh;
	}

	return NULL;
}
