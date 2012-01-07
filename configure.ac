#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.64])
AC_INIT([heimdal_an2ln_cdb], [1.0], [elric@imrryr.org])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([cf])

AM_INIT_AUTOMAKE([foreign 1.10.3])
AM_MAINTAINER_MODE

dnl Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CPP
AC_DISABLE_STATIC
AC_PROG_LIBTOOL

LT_PREREQ([2.2])
# L#T_INIT([shared])

# AM_CONDITIONAL(ENABLE_SHARED, test "$enable_shared" = "yes")

AC_ARG_WITH([heimdal],
	    [AC_HELP_STRING([--with-heimdal=<DIR>],
			    [choose the Heimdal dir])],
	    [heimdir=$withval],
	    [heimdir=/usr])

if test -d ${heimdir}; then
	CPPFLAGS="$CPPFLAGS -I$heimdir/include"
	LDFLAGS="$LDFLAGS -L$heimdir/lib"
fi

AC_ARG_WITH([cdb],
	    [AC_HELP_STRING([--with-cdb=<DIR>],
			    [choose the CDB dir])],
	    [cdbdir=$withval],
	    [cdbdir=/usr])

if test -d ${cdbdir}; then
	CPPFLAGS="$CPPFLAGS -I$cdbdir/include"
	LDFLAGS="$LDFLAGS $cdbdir/lib/libcdb_pic.a"
fi

AC_CHECK_HEADERS([krb5/krb5.h krb5.h], break,,)

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
