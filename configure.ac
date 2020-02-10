#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([libncot], [0.0.1], [net_seeker@web.de])
AC_CONFIG_SRCDIR([src/ncot.c])
AC_CONFIG_HEADERS([autoconfig.h])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

# Enable "automake" to simplify creating makefiles:
AM_INIT_AUTOMAKE([subdir-objects -Wall -Werror])

# Doxygen stuff, hopefully portable between msys2-mingw/linux
AC_ARG_WITH([doxygen],
	AS_HELP_STRING([--without-doxygen],
	[do not build doxygen based documentation]))

AS_IF([test "x$with_doxygen" != "xno"],
	    [AC_CHECK_PROG([have_doxy], [doxygen], [yes], [no])],
	    [have_doxy=no])

AS_IF([test "x$with_doxygen" != "xno"],
	    [AC_CHECK_PROG([have_dot], [dot], [yes], [no])],
	    [have_dot=no])

AS_IF([test "x$with_doxygen" != "xno"],
	    [AC_CHECK_PROG([have_pdflatex], [pdflatex], [yes], [no])],
	    [have_pdflatex=no])

AS_IF([test "x$have_doxy" = "xyes"],
      [],
      [AS_IF([test "x$with_doxygen" = "xyes"],
             [AC_MSG_ERROR([docs build by doxygen requested but doxygen not found])
      ])
])

AS_IF([test "x$have_dot" = "xyes"],
      [],
      [AS_IF([test "x$with_doxygen" = "xyes"],
             [AC_MSG_ERROR([docs build by doxygen requested, doxygen needs dot but dot not found])
      ])
])

AS_IF([test "x$have_pdflatex" = "xyes"],
      [],
      [AS_IF([test "x$with_doxygen" = "xyes"],
             [AC_MSG_ERROR([docs build by doxygen requested, doxygen needs pdflatex but pdflatex not found])
      ])
])

AM_CONDITIONAL([HAVE_DOXYGEN], [test -n "$with_doxygen"])
AM_COND_IF([HAVE_DOXYGEN], [AC_CONFIG_FILES([docs/Doxyfile])])
AM_COND_IF([HAVE_DOXYGEN], [AC_CONFIG_FILES([docs/Makefile])])
    
# ossp-uuid appears under uuid in msys2-mingw64(32?)
AC_ARG_WITH([plainuuid],
	AS_HELP_STRING([--with-plainuuid],
	[under msys2/mingw our handcrafted ossp-uuid appears as plain uuid through pkg-config])
)
	
# Samples currently work only under Linux
AC_ARG_ENABLE([samples],
	AS_HELP_STRING([--enable-samples],
	[Build generic crypto sample programs]),
[case "${enableval}" in
  yes) samples=true ;;
  no)  samples=false ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --enable-samples]) ;;
esac],[samples=false])
AM_CONDITIONAL([SAMPLES], [test x$samples = xtrue])

AC_CONFIG_FILES([Makefile src/Makefile tests/Makefile])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AM_PROG_AR

# This is needed for msys2-mingw builds
LT_INIT([win32-dll])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([errno.h fcntl.h stdio.h stdlib.h unistd.h sys/uio.h])
AC_CHECK_HEADERS([sys/select.h sys/socket.h sys/ioctl.h sys/time.h])
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h])

# This is a workaround different package names under msys-mingw/linux
AC_CANONICAL_HOST
case "$host" in
	*mingw* | *cygwin*)
		LT_LDFLAGS="-no-undefined -lws2_32"
		;;
	*)
		LT_LDFLAGS=""
		;;
esac

AC_SUBST(LT_LDFLAGS)

case $host in
  *-*-cygwin* | *-*-cegcc*)
    # These are POSIX-like systems using BSD-like sockets API.
    ;;
  *)
    AC_CHECK_HEADERS([windows.h winsock2.h ws2tcpip.h])
    ;;
esac

#AC_DEFINE([WINVER], [0x0501], 'Minimum plattform winxp for mingw crossbuild')

AC_CANONICAL_HOST
AC_LIBTOOL_WIN32_DLL
# Checks for libraries.
PKG_CHECK_MODULES([CHECK], [check >= 0.9.8])
PKG_CHECK_MODULES([POPT], [popt >= 1.16])
AS_IF([test "x$with_plainuuid" = "xyes"],
	    [PKG_CHECK_MODULES([UUID], [uuid >= 1.6.2])],
	    [PKG_CHECK_MODULES([UUID], [ossp-uuid >= 1.6.2])]
)
PKG_CHECK_MODULES([GNUTLS], [gnutls >= 3.5.8 ])
PKG_CHECK_MODULES([JSONC], [json-c >= 0.12 ])
AC_SUBST([GNUTLS_CFLAGS])
AC_SUBST([GNUTLS_LIBS])
AC_SUBST([POPT_CFLAGS])
AC_SUBST([POPT_LIBS])
AC_SUBST([UUID_CFLAGS])
AC_SUBST([UUID_LIBS])
AC_SUBST([JSONC_CFLAGS])
AC_SUBST([JSONC_LIBS])

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

AC_CHECK_FUNCS([strtol])
AC_OUTPUT

# Finally, print our results

echo
echo "=========================================="
echo "Host is: $host"
echo "=========================================="
echo "Summary of options:"
echo


if test "xyes" = x"$with_plainuuid"; then
    result="yes"
else
    result="no"
fi
echo "use plain uuid as ossp-uuid........... $result"

if test "xfalse" = x"$samples"; then
    result="no"
else
    result="yes"
fi
echo "compile samples....................... $result"

if test "xyes" = x"$with_doxygen"; then
    result="yes"
else
    result="no"
fi
echo "generate Doxygen based documentation.. $result"

echo "=========================================="
