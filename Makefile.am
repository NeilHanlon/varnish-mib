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
ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src
EXTRA_DIST=git2chg.awk

.PHONY: ChangeLog
ChangeLog:
	$(AM_V_GEN)if test -d .git; then                                   \
	  git log --pretty='format:%ct  %an  <%ae>%n%n%s%n%n%b%n' |        \
            awk -f $(top_srcdir)/git2chg.awk > ChangeLog;  \
        fi
