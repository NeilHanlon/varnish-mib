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

#include "varnish_mib.h"

static int
send_ban_cmd(vcli_conn_t *conn, const char *expr)
{
	if (vcli_asprintf(conn, "ban %s\n", expr) || vcli_write(conn))
		return 1;

	if (vcli_read_response(conn))
		return 1;
	
	if (conn->resp != CLIS_OK) {
		snmp_log(LOG_ERR, "command rejected: %u %s\n",
			 conn->resp, conn->base);
		return 1;
	}
	return 0;
}

int
varnish_ban(netsnmp_agent_request_info   *reqinfo,
	    netsnmp_request_info         *requests,
	    struct VSM_data              *vd)
{
	int rc;
	struct vcli_conn conn;
	size_t len = requests->requestvb->val_len;
	char *expr = malloc(len + 1);
	
	if (!expr) {
                snmp_log(LOG_ERR, "out of memory\n");
		return SNMP_ERR_GENERR;
	}
	memcpy(expr, requests->requestvb->val.string, len);
	expr[len] = 0;
	DEBUGMSGTL(("vcli_mib", "ban %s\n", expr));
	rc = vcli_connect(vd, &conn);
	if (rc == SNMP_ERR_NOERROR) {
		rc = send_ban_cmd(&conn, expr);
		vcli_disconnect(&conn);
	}
	free(expr);
	return rc ? SNMP_ERR_GENERR : SNMP_ERR_NOERROR;
}

