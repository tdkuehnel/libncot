lib_LTLIBRARIES = libncot.la
libncot_la_SOURCES = ncot.c ncot.h debug.h log.c log.h utlist.h context.c context.h arg.c arg.h connection.h connection.c node.h node.c packet.c packet.h select.c select.h init.c init.h shell.c

include_HEADERS = ncot.h

#libncot_la_CFLAGS = @UUID_CFLAGS@
#libncot_la_LIBADD = @UUID_LIBS@ @GNUTLS_LIBS@
libncot_la_CFLAGS = @GNUTLS_CFLAGS@
libncot_la_LIBADD = @GNUTLS_LIBS@

bin_PROGRAMS = ncot ncotd cmdi

ncot_SOURCES = ncot.c
ncot_LDADD = libncot.la @GNUTLS_LIBS@ @EXTRA_LD_ADD@

ncotd_SOURCES = ncotd.c
ncotd_LDADD = libncot.la @GNUTLS_LIBS@ @EXTRA_LD_ADD@

cmdi_SOURCES = interpreter.c
cmdi_LDADD = -lm
##simple_SOURCES = simple.c simple.h
##cpw_LDADD = @AVUTIL_LIBS@
##cpw_CFLAGS = @AVUTIL_CFLAGS@
