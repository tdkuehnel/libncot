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
AC_CONFIG_FILES([Makefile src/Makefile tests/Makefile])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AM_PROG_AR

LT_INIT

# Checks for libraries.
PKG_CHECK_MODULES([CHECK], [check >= 0.9.8])
PKG_CHECK_MODULES([CONFUSE], [libconfuse >= 3.2])
PKG_CHECK_MODULES([UUID], [ossp-uuid >= 0.1])
#PKG_CHECK_MODULES([LIBRESSL], [libtls >= 18.1.0])
PKG_CHECK_MODULES([GNUTLS], [gnutls >= 0.29.2 ])
# PKG_CHECK_MODULES([AVUTIL], [libavutil >= 54])
# AC_SUBST([AVUTIL_CFLAGS])
# AC_SUBST([AVUTIL_LIBS])
AC_SUBST([GNUTLS_CFLAGS])
AC_SUBST([GNUTLS_LIBS])

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

AC_CHECK_FUNCS([strtol])
AC_OUTPUT
