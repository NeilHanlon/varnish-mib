# This file is part of varnish-mib -*- automake -*-
# Copyright (C) 2014-2015 Sergey Poznyakoff
#
# varnish-mib is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
#
# varnish-mib is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with varnish-mib.  If not, see <http://www.gnu.org/licenses/>.

dlmoddir=@DLMODDIR@
dlmod_LTLIBRARIES = varnish-mib.la

varnish_mib_la_SOURCES = \
 auth.c\
 ban.c\
 betab.c\
 sha256.c\
 sha256.h\
 varnish_mib.c\
 varnish_mib.h\
 vcli.c

BUILT_SOURCES = \
 varnish_mib.c\
 varnish_mib.h

varnish_mib.c varnish_mib.h: varnish_mib.mib2c VARNISH-MIB.txt

.mib2c.c:
	MIBDIRS=${top_srcdir}/src:${NET_SNMP_MIBDIRS} MIBS="+VARNISH-MIB" \
	 mib2c -c $< -f $@ varnish

#NET_SNMP_INCLUDES = `$(NET_SNMP_CONFIG) --cflags`
#NET_SNMP_INCLUDES =
NET_SNMP_LIBS = `$(NET_SNMP_CONFIG) --libs`
NET_SNMP_EXLIBS = `$(NET_SNMP_CONFIG) --external-libs`
NET_SNMP_MIBDIRS = `net-snmp-config --mibdirs`

AM_LDFLAGS = \
 -module \
 -export-dynamic\
 -avoid-version \
 -rpath '$(dlmoddir)'\
 ${VARNISHAPI_LIBS}\
 $(NET_SNMP_LIBS)\
 $(NET_SNMP_EXLIBS)

AM_CPPFLAGS=-I. ${VARNISHAPI_CFLAGS}

mibdir=@MIBDIR@
mib_DATA = VARNISH-MIB.txt

dist_man_MANS = varnish-mib.8

EXTRA_DIST = VARNISH-MIB.txt varnish_mib.mib2c
