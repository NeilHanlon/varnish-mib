/* This file is part of varnish-mib -*- c -*-
   Copyright (C) 2014 Sergey Poznyakoff

   Varnish-mib is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   Varnish-mib is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with varnish-mib.  If not, see <http://www.gnu.org/licenses/>.
*/
#include <config.h>
#include <stdlib.h>
#include <stdint.h>

#include <vapi/vsc.h>
#include <vapi/vsm.h>
#include <vcli.h>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

typedef struct vcli_conn {
	int fd;
	char *secret;
	int resp;
	char *base;
	size_t bufmax;
	size_t bufsize;
} vcli_conn_t;

int vcli_write(vcli_conn_t *conn);
int vcli_read_response(vcli_conn_t *conn);
int vcli_vasprintf(vcli_conn_t *conn, const char *fmt, va_list ap);
int vcli_asprintf(vcli_conn_t *conn, const char *fmt, ...);
void vcli_disconnect(vcli_conn_t *conn);
int vcli_connect(struct VSM_data *vd, vcli_conn_t *conn);


int varnish_auth_response(const char *file, const char *challenge,
			  char response[CLI_AUTH_RESPONSE_LEN + 1]);

int varnish_ban(netsnmp_agent_request_info   *reqinfo,
		netsnmp_request_info         *requests,
		struct VSM_data *vd);

