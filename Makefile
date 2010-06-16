GLIB_CPPFLAGS		= $$(pkg-config --cflags glib-2.0)
GLIB_LIBS		= $$(pkg-config --libs glib-2.0)
CONFUSE_CPPFLAGS	= $$(pkg-config --cflags libconfuse)
CONFUSE_LIBS		= $$(pkg-config --libs libconfuse)

#CC		= gcc
CC		= clang
CFLAGS		= -O3 -g
CPPFLAGS	=  $(GLIB_CPPFLAGS) $(CONFUSE_CPPFLAGS)
LDFLAGS		= -L/usr/local/lib
LIBS		= -levent $(GLIB_LIBS) $(CONFUSE_LIBS)

# If you want to use suexec to run CGI programs as the user
# instead of the web server, you need to define these.
CPPFLAGS	+= -DSUEXEC=\"/home/river/tws/suexec\"
SUEXEC_CPPFLAGS =				\
	-DSUEXEC_USER=\"www\"			\
	-DSUEXEC_UID_MIN=100			\
	-DSUEXEC_GID_MIN=100			\
	-DSUEXEC_USERDIR=\"public_html\"	\
	-DSUEXEC_LOGFILE=\"/home/river/tws/suexec.log\"		\
	-DSUEXEC_DOCROOT=\"/home/river/tws/docs\" \
	-DSUEXEC_PATH=\"/bin:/usr/bin:/usr/local/bin\"

OBJS		= \
	main.o		\
	config.o	\
	net.o		\
	log.o		\
	file.o		\
	cgi.o		\
	util.o

all: tws suexec suexec_weak
tws: $(OBJS)
	@echo Link tws
	@$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) -o tws $(LIBS)

.c.o:
	@echo Compile $<
	@$(CC) $(CPPFLAGS) $(CFLAGS) -c $<

suexec: suexec.o
	@echo Link suexec
	@$(CC) $(CFLAGS) $(SUEXEC_CPPFLAGS) suexec.o -o suexec

suexec_weak: suexec_weak.o
	@echo Link suexec_weak
	@$(CC) $(CFLAGS) $(SUEXEC_CPPFLAGS) suexec_weak.o -o suexec_weak

suexec.o: suexec.c
	@echo Compile suexec.c
	@$(CC) $(CFLAGS) $(SUEXEC_CPPFLAGS) -c suexec.c

suexec_weak.o: suexec_weak.c
	@$(CC) $(CFLAGS) $(SUEXEC_CPPFLAGS) -c suexec_weak.c

clean:
	rm -f tws $(OBJS) suexec suexec_weak
