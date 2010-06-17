AC_PREREQ(2.62)
AC_INIT(TWS, 1.0_alpha, river@TCX.ORG.UK)
AC_CONFIG_SRCDIR([tws/main.c])
AC_CONFIG_HEADERS([setup.h])

AC_PROG_CC
AC_PROG_INSTALL

PKG_CHECK_MODULES([GLIB], [glib-2.0])
PKG_CHECK_MODULES([CONFUSE], [libconfuse])

libevent_include=""
libevent_lib=""
AC_ARG_WITH(libevent,
	AC_HELP_STRING([--with-libevent=PATH],[base directory for libevent]),
	[
		if test "x$withval" != "no"; then
			libevent_include="$withval/include"
			libevent_lib="$withval/lib"
		fi
	])

AC_ARG_WITH([libevent-include],
	AC_HELP_STRING([--with-libevent-include=PATH],[include directory for libevent]),
	[
		if test "x$withval" != "no"; then
			libevent_include="$withval"
		fi
	])

AC_ARG_WITH([libevent-lib],
	AC_HELP_STRING([--with-libevent-lib=PATH],[library directory for libevent]),
	[
		if test "x$withval" != "no"; then
			libevent_include="$withval"
		fi
	])

if test "x$libevent_include" != "x"; then
	CPPFLAGS="$CPPFLAGS -I$libevent_include"
fi
if test "x$libevent_lib" != "x"; then
	LDFLAGS="$LDFLAGS -L$libevent_lib"
fi

AC_CHECK_HEADER(event.h, [], [
	AC_MSG_ERROR([libevent is required to build TWS])
	exit 1
],)
AC_CHECK_LIB(event, event_init, [], [
	AC_MSG_ERROR([libevent is required to build TWS])
	exit 1
],)

zlib_include=""
zlib_lib=""
AC_ARG_WITH(zlib,
	AC_HELP_STRING([--with-zlib=PATH],[base directory for zlib]),
	[
		if test "x$withval" != "no"; then
			zlib_include="$withval/include"
			zlib_lib="$withval/lib"
		fi
	])

AC_ARG_WITH([zlib-include],
	AC_HELP_STRING([--with-zlib-include=PATH],[include directory for zlib]),
	[
		if test "x$withval" != "no"; then
			zlib_include="$withval"
		fi
	])

AC_ARG_WITH([zlib-lib],
	AC_HELP_STRING([--with-zlib-lib=PATH],[library directory for zlib]),
	[
		if test "x$withval" != "no"; then
			zlib_include="$withval"
		fi
	])

if test "x$zlib_include" != "x"; then
	CPPFLAGS="$CPPFLAGS -I$zlib_include"
fi
if test "x$zlib_lib" != "x"; then
	LDFLAGS="$LDFLAGS -L$zlib_lib"
fi

AC_CHECK_HEADER(zlib.h, [], [
	AC_MSG_ERROR([zlib is required to build TWS])
	exit 1
],)
AC_CHECK_LIB(z, gzopen, [], [
	AC_MSG_ERROR([zlib is required to build TWS])
	exit 1
],)

suexec_user="www"
suexec_minuid="100"
suexec_mingid="100"
suexec_docroot="/var/www"
suexec_userdir="public_html"
suexec_path="/bin:/usr/bin:/usr/local/bin"
suexec_log="/var/log/tws/suexec"

AC_ARG_ENABLE(suexec,
	AC_HELP_STRING([--enable-suexec],[Enable suexec binary]),
	[AC_SUBST(SUEXEC, suexec)])
AC_ARG_ENABLE(suexec-weak,
	AC_HELP_STRING([--enable-suexec-weak],[Enable weak suexec binary]),
	[AC_SUBST(SUEXEC_WEAK, suexec_weak)])
AC_ARG_WITH(suexec-user,
	[AC_HELP_STRING([--with-suexec-user=USERNAME],[User suexec will run as (default: www)])],
	[suexec_user="$withval"])
AC_ARG_WITH(suexec-min-uid,
	[AC_HELP_STRING([--with-suexec-min-uid=UID],[Minimum UID suexec will run CGIs as (default: 100)])],
	[suexec_min_uid="$withval"])
AC_ARG_WITH(suexec-min-gid,
	[AC_HELP_STRING([--with-suexec-min-gid=GID],[Minimum GID suexec will run CGIs as (default: 100)])],
	[suexec_min_gid="$withval"])
AC_ARG_WITH(suexec-docroot,
	[AC_HELP_STRING([--with-suexec-docroot=PATH],[Document root for suexec (default: /var/www)])],
	[suexec_docroot="$withval"])
AC_ARG_WITH(suexec-userdir,
	[AC_HELP_STRING([--with-suexec-userdir=DIR],[Per-user CGI directory (default: public_html)])],
	[suexec_userdir="$withval"])
AC_ARG_WITH(suexec-path,
	[AC_HELP_STRING([--with-suexec-path=PATH],[Default PATH for CGI programs (default: /bin:/usr/bin:/usr/local/bin)])],
	[suexec_path="$withval"])
AC_ARG_WITH(suexec-log,
	[AC_HELP_STRING([--with-suexec-log=PATH],[suexec logfile path (default: /var/log/tws/suexec)])],
	[suexec_log="$withval"])

AC_SUBST([SUEXEC_USER], [$suexec_user])
AC_SUBST([SUEXEC_MIN_UID], [$suexec_minuid])
AC_SUBST([SUEXEC_MIN_GID], [$suexec_mingid])
AC_SUBST([SUEXEC_DOCROOT], [$suexec_docroot])
AC_SUBST([SUEXEC_USERDIR], [$suexec_userdir])
AC_SUBST([SUEXEC_PATH], [$suexec_path])
AC_SUBST([SUEXEC_LOG], [$suexec_log])

AC_CONFIG_FILES([
	Makefile 
	tws/Makefile 
	suexec/Makefile 
	suexec_weak/Makefile
])
AC_OUTPUT
