lib_LTLIBRARIES = libncot.la
libncot_la_SOURCES = ncot.c ncot.h debug.h log.c log.h utlist.h context.c context.h arg.c arg.h

include_HEADERS = ncot.h

libnct_la_CFLAGS = @UUID_CFLAGS@
libnct_la_LIBADD = @UUID_LIBS@ @GNUTLS_LIBS@

bin_PROGRAMS = ncot ncotd
ncot_SOURCES = ncotclient.c
ncot_LDADD = libnct.la @GNUTLS_LIBS@

ncotd_SOURCES = ncotd.c
ncotd_LDADD = libncot.la @GNUTLS_LIBS@

##simple_SOURCES = simple.c simple.h
##cpw_LDADD = @AVUTIL_LIBS@
##cpw_CFLAGS = @AVUTIL_CFLAGS@
