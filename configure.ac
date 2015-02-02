# This file is part of Varnish-mib -*- autoconf -*-
# Copyright (C) 2014-2015 Sergey Poznyakoff
#
# Varnish-mib is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
#
# Varnish-mib is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Varnish-mib.  If not, see <http://www.gnu.org/licenses/>.

AC_PREREQ(2.69)
AC_INIT([varnish-mib], 1.0.90, [gray@gnu.org])
AC_CONFIG_SRCDIR(src/varnish_mib.mib2c)
AM_CONFIG_HEADER(config.h)
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

AC_CANONICAL_SYSTEM
AC_LANG(C)
AM_INIT_AUTOMAKE([gnu tar-ustar])

AC_GNU_SOURCE
AC_PROG_CC
AC_PROG_CC_STDC
if test "x$ac_cv_prog_cc_c99" = xno; then
  AC_MSG_ERROR([could not find a C99 compatible compiler])
fi
AC_PROG_CPP

AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_PROG_MAKE_SET

# Check for pkg-config
PKG_PROG_PKG_CONFIG

# Checks for Varnish
PKG_CHECK_MODULES([VARNISHAPI], [varnishapi >= 4.0])

# Check for Net-SNMP
AC_PATH_PROG([NET_SNMP_CONFIG], net-snmp-config, none, $PATH)
if test "$NET_SNMP_CONFIG" = "none"; then
  AC_MSG_ERROR([cannot find Net-SNMP (net-snmp-config not found)])
fi
AC_SUBST(NET_SNMP_CONFIG)

# Checks for header files.
AC_HEADER_STDC

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T

# Directories
AC_SUBST([DLMODDIR],['$(libdir)/snmp'])
AC_ARG_WITH([dlmoddir],
 [AC_HELP_STRING([--with-dlmoddir=DIR],
                 [installation directory for net-snmp loadable agents])],
 [case $withval in
  /*) DLMODDIR=$withval;;
  *)  AC_MSG_ERROR([argument to --with-dlmoddir must be absolute pathname])
  esac])

AC_SUBST([MIBDIR],['$(datarootdir)/snmp'])
AC_ARG_WITH([mibdir],
 [AC_HELP_STRING([--with-mibdir=DIR],
                 [installation directory for MIB files])],
 [case $withval in
  /*) MIBDIR=$withval;;
  *)  AC_MSG_ERROR([argument to --with-mibdir must be absolute pathname])
  esac])

  
# Generate output
AC_CONFIG_FILES([
    Makefile
    src/Makefile
])
AC_OUTPUT
