VERSION=0:0:0

libncot_la_SOURCES = ncot.c ncot.h debug.h log.c log.h utlist.h context.c context.h arg.c arg.h connection.h connection.c node.h node.c packet.c packet.h select.c select.h init.c init.h shell.c shell.h identity.c identity.h shell_node.c shell_connection.c shell_connection.h shell_identity.c shell_context.c shell_connect.c shell_connect.h policy.h policy.c ring.h ring.c
libncot_la_LDFLAGS = -version-info ${VERSION} -no-undefined

lib_LTLIBRARIES = libncot.la

include_HEADERS = ncot.h

#libncot_la_CFLAGS = @UUID_CFLAGS@
#libncot_la_LIBADD = @UUID_LIBS@ @GNUTLS_LIBS@
libncot_la_CFLAGS = @GNUTLS_CFLAGS@ @POPT_CFLAGS@ @UUID_CFLAGS@ @JSONC_CFLAGS@ @SSH_CFLAGS@
libncot_la_LIBADD = @GNUTLS_LIBS@ @POPT_LIBS@ @UUID_LIBS@ @JSONC_LIBS@ @SSH_LIBS@

bin_PROGRAMS = ncot cmdi sshserver sshclient sshserver2

ncot_SOURCES = ncot.c
ncot_LDADD = libncot.la @GNUTLS_LIBS@ @POPT_LIBS@ @UUID_LIBS@ @JSONC_LIBS@ @SSH_LIBS@

cmdi_SOURCES = interpretersample.c
cmdi_LDADD = -lm
##simple_SOURCES = simple.c simple.h
##cpw_LDADD = @AVUTIL_LIBS@
##cpw_CFLAGS = @AVUTIL_CFLAGS@

sshserver_SOURCES = sshserver.c log.c
sshserver_LDADD = @SSH_LIBS@

sshserver2_SOURCES = sshserver2.c log.c
sshserver2_LDADD = @SSH_LIBS@

sshclient_SOURCES = sshclient.c
sshclient_LDADD = @SSH_LIBS@

