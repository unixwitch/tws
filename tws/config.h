/*
 * Copyright (c) 2010 River Tarnell.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef TWS_CONFIG_H
#define TWS_CONFIG_H

#define DEFAULT_CONFIG ETCDIR "/tws.conf"

#include	<glib.h>

typedef enum {
	PR_CGI,
	PR_FASTCGI
} interp_proto_t;

typedef struct {
	char		*path;
	GHashTable	*types;
	interp_proto_t	 protocol;
} interp_t;

typedef struct {
	char		*name;
	char		*docroot;
	char		*userdir;
	char		*userdir_prefix;
	char		*deftype;
	GPtrArray	*aliases;
	GPtrArray	*interps;
	GPtrArray	*indexes;
	GHashTable	*cgidirs;
	GHashTable	*cgitypes;
	int		 suexec_enable;
	int		 minuid;
} vhost_t;

typedef struct {
	char	*addr;
	char	*port;
	int	 backlog;
	int	 protocol;
} tws_listen_t;

typedef struct {
	GArray		*vhosts;
	GArray		*listeners;
	int		 timeout;
	char		*user;
	char		*group;
	int		 use_sendfile;
	GHashTable	*mimetypes;
	char		*deftype;
	GPtrArray	*indexes;
	int		 dodns;
	int		 compr_level;
	int		 compr_cgi;
	GPtrArray	*compr_types;
} tws_config_t;

tws_config_t	*curconf;

	tws_config_t	*config_load(const char *file);
	void		 config_free(tws_config_t *);

	vhost_t		*config_find_vhost(const char *host);

#endif	/* TWS_CONFIG_H */
