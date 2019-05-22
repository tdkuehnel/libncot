bin_PROGRAMS = tcpserver 

tcpserver_SOURCES = tcpserver.c
tcpserver_LDADD = @GNUTLS_LIBS@

TESTS = check_helper check_node check_connection
check_PROGRAMS = check_helper check_ncot check_node check_connection

check_helper_SOURCES = check_helper.c
check_helper_CFLAGS = @CHECK_CFLAGS@
check_helper_LDADD = @CHECK_LIBS@ @GNUTLS_LIBS@  @UUID_LIBS@ 

check_ncot_SOURCES = check_ncot.c $(top_builddir)/src/ncot.h ../src/log.c ../src/ncot.c 
check_ncot_CFLAGS = @CHECK_CFLAGS@
check_ncot_LDADD = @CHECK_LIBS@ @GNUTLS_LIBS@  @UUID_LIBS@ 

check_node_SOURCES = check_node.c $(top_builddir)/src/node.h ../src/log.c ../src/node.c 
check_node_CFLAGS = @CHECK_CFLAGS@
check_node_LDADD = @CHECK_LIBS@ @GNUTLS_LIBS@  @UUID_LIBS@ 

check_connection_SOURCES = check_connection.c 	\
	$(top_builddir)/src/connection.h	\
	$(top_builddir)/src/log.c  		\
	$(top_builddir)/src/connection.c  	\
	$(top_builddir)/src/ncot.c

check_connection_CFLAGS = @CHECK_CFLAGS@
check_connection_LDADD = @CHECK_LIBS@ @GNUTLS_LIBS@  @UUID_LIBS@ 

