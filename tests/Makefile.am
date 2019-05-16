TESTS = check_helper check_ncot
check_PROGRAMS = check_helper check_ncot

check_helper_SOURCES = check_helper.c $(top_builddir)/src/ncot.h ../src/log.c ../src/ncot.c 
check_helper_CFLAGS = @CHECK_CFLAGS@
check_helper_LDADD = @CHECK_LIBS@ @GNUTLS_LIBS@  @UUID_LIBS@ 

check_ncot_SOURCES = check_ncot.c $(top_builddir)/src/ncot.h ../src/log.c ../src/ncot.c 
check_ncot_CFLAGS = @CHECK_CFLAGS@
check_ncot_LDADD = @CHECK_LIBS@ @GNUTLS_LIBS@  @UUID_LIBS@ 

