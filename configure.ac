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

AC_CHECK_PROGS([DOXYGEN], [doxygen])
if test -z "$DOXYGEN"; then
   AC_MSG_WARN([Doxygen not found - continue without Doxygen support])
fi
AC_CHECK_PROGS([DOT], [dot])
if test -z "$DOT"; then
   AC_MSG_ERROR([Doxygen needs dot, please install dot first])
fi
AC_CHECK_PROGS([PDFLATEX], [pdflatex])
if test -z "$PDFLATEX"; then
   AC_MSG_ERROR([Doxygen needs pdflatex program, it is part of TeX http://www.tug.org/texlive/acquire-netinstall.html])
fi
AM_CONDITIONAL([HAVE_DOXYGEN], [test -n "$DOXYGEN"])
AM_COND_IF([HAVE_DOXYGEN], [AC_CONFIG_FILES([docs/Doxyfile])])
AM_COND_IF([HAVE_DOXYGEN], [AC_CONFIG_FILES([docs/Makefile])])

AC_CONFIG_FILES([Makefile src/Makefile tests/Makefile])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AM_PROG_AR

LT_INIT([win32-dll])

#AC_ARG_WITH([ossp-uuid],
#            [AS_HELP_STRING([--without-ossp-uuid],
#              [win32 does not need ossp-uuid @<:@default=yes@:>@])],
#            [],
#            [with_ossp_uuid=yes])

#AS_IF([test "x$with_ossp-uuid" = "xyes"], [
#   PKG_CHECK_MODULES([UUID], [ossp-uuid >= 0.1])
#])

# Checks for header files.
# AC_HEADER_STDC
AC_CHECK_HEADERS([errno.h fcntl.h stdio.h stdlib.h unistd.h sys/uio.h])
AC_CHECK_HEADERS([sys/select.h sys/socket.h sys/ioctl.h sys/time.h])
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h])

AC_CANONICAL_HOST
case "$host" in
	*mingw* | *cygwin*)
		LT_LDFLAGS="-no-undefined"
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
#PKG_CHECK_MODULES([CONFUSE], [libconfuse >= 3.2])
#PKG_CHECK_MODULES([UUID], [ossp-uuid >= 0.1])
PKG_CHECK_MODULES([UUID], [ossp-uuid >= 0.1])
#PKG_CHECK_MODULES([LIBRESSL], [libtls >= 18.1.0])
PKG_CHECK_MODULES([GNUTLS], [gnutls >= 3.5.8 ])
PKG_CHECK_MODULES([JSONC], [json-c >= 0.12 ])
PKG_CHECK_MODULES([SSH], [libssh >= 0.7.3 ])
PKG_CHECK_MODULES([SSH2], [libssh2 >= 1.7.0 ])
# PKG_CHECK_MODULES([AVUTIL], [libavutil >= 54])
# AC_SUBST([AVUTIL_CFLAGS])
# AC_SUBST([AVUTIL_LIBS])
AC_SUBST([GNUTLS_CFLAGS])
AC_SUBST([GNUTLS_LIBS])
AC_SUBST([POPT_CFLAGS])
AC_SUBST([POPT_LIBS])
AC_SUBST([UUID_CFLAGS])
AC_SUBST([UUID_LIBS])
AC_SUBST([JSONC_CFLAGS])
AC_SUBST([JSONC_LIBS])
AC_SUBST([SSH2_CFLAGS])
AC_SUBST([SSH2_LIBS])
AC_SUBST([SSH_CFLAGS])
AC_SUBST([SSH_LIBS])
echo "$SSH_LIBS"
echo "$POPT_LIBS"
echo "$GNUTLS_LIBS"
# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

AC_CHECK_FUNCS([strtol])
AC_OUTPUT
