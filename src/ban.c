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
#include <ctype.h>

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
	DEBUGMSGTL(("varnish_ban", "setting ban %s\n", expr));
	rc = vcli_connect(vd, &conn);
	if (rc == SNMP_ERR_NOERROR) {
		rc = send_ban_cmd(&conn, expr);
 		vcli_disconnect(&conn);
	}
	free(expr);
	return rc ? SNMP_ERR_GENERR : SNMP_ERR_NOERROR;
}

unsigned banTable_timeout = 60;

int
varnish_mib_timeout_parser(const char *token, char *line, unsigned *retval)
{
	char *p;
	unsigned long n = strtoul(line, &p, 10);

	if (*p) {
		if (isspace(*p)) {
			while (*p && isspace(*p))
				++p;
			if (*p) {
				config_perror("too many arguments");
				return 1;
			}
		} else {
			config_perror("invalid timeout value");
			return 1;
		}
	}
	
	if (n > UINT_MAX) {
		config_perror("timeout value out of allowed range");
		return 1;
	}
	
	*retval = n;
	return 0;
}

void
varnish_ban_table_timeout_parser(const char *token, char *line)
{
	varnish_mib_timeout_parser(token, line, &banTable_timeout);
}

/*
 * create a new row in the table 
 */
static struct banTable_entry *
create_entry(netsnmp_tdata *table_data, long idx, struct banTable_entry *ent)
{
	struct banTable_entry *entry;
	netsnmp_tdata_row *row;

	entry = SNMP_MALLOC_TYPEDEF(struct banTable_entry);
	if (!entry)
		return NULL;
	
	row = netsnmp_tdata_create_row();
	if (!row) {
		SNMP_FREE(entry);
		return NULL;
	}
	row->data = entry;
	*entry = *ent;
	
	entry->banIndex = idx;
	netsnmp_tdata_row_add_index(row, ASN_INTEGER,
				    &entry->banIndex,
				    sizeof(entry->banIndex));
	if (table_data)
		netsnmp_tdata_add_row(table_data, row);
	return entry;
}

#define TMSEC(t) (((t)->tm_hour * 60 + (t)->tm_min) * 60 + (t)->tm_sec)

static int
utc_offset (void)
{
	time_t t = time (NULL);
	struct tm ltm = *localtime (&t);
	struct tm gtm = *gmtime (&t);
	int d = TMSEC (&ltm) - TMSEC (&gtm);
	if (!(ltm.tm_year = gtm.tm_year && ltm.tm_mon == gtm.tm_mon))
		d += 86400;
	return d / 60;
}

/* Refill the ban table */
int
banTable_load(netsnmp_cache *cache, void *vmagic)
{
	netsnmp_tdata  *table = (netsnmp_tdata *) vmagic;
	long           idx = 0;
	int rc;
	struct vcli_conn conn;
	char *p;
	struct VSM_data *vd;
	
	DEBUGMSGTL(("varnish_ban", "reloading ban table"));
	vd = varnish_get_vsm_data();
	rc = vcli_connect(vd, &conn);
	if (rc != SNMP_ERR_NOERROR)
	    return rc;
	
	if (vcli_asprintf(&conn, "ban.list\n") || vcli_write(&conn))
		return SNMP_ERR_GENERR;
	
	if (vcli_read_response(&conn))
		return SNMP_ERR_GENERR;
	
	if (conn.resp != CLIS_OK) {
		snmp_log(LOG_ERR, "ban.list command rejected: %u %s\n",
			 conn.resp, conn.base);
		return SNMP_ERR_GENERR;
	}
	
	p = conn.base;
	while (p < conn.base + conn.bufsize) {
		char *q;
		struct banTable_entry e;
		struct tm *tm;
		time_t t;
		int n;
		
		if (*p == '\n') {
			++p;
			continue;
		}
		e.banIndex = idx;
		t = strtoul(p, &q, 10);
		if (*q != '.') {
			p = strchr(p, '\n');
			if (!p)
			    break;
			continue;
		}
		++q;

		e.banTime_len = 11;
		e.banTime = malloc(e.banTime_len + 1);
		if (!e.banTime) {
			vcli_disconnect(&conn);
			snmp_log(LOG_ERR, "out of memory\n");
			return SNMP_ERR_GENERR;
		}
		tm = localtime(&t);
		/*    A date-time specification.
          
                      field  octets  contents                  range
                      -----  ------  --------                  -----
                        1      1-2   year*                     0..65536
                        2       3    month                     1..12
                        3       4    day                       1..31
                        4       5    hour                      0..23
                        5       6    minutes                   0..59
                        6       7    seconds                   0..60
                                     (use 60 for leap-second)
                        7       8    deci-seconds              0..9
                        8       9    direction from UTC        '+' / '-'
                        9      10    hours from UTC*           0..13
                       10      11    minutes from UTC          0..59

		       * Notes:
                       - the value of year is in network-byte order
		*/
		n = tm->tm_year % 100;
		e.banTime[0] = n >> 8;
		e.banTime[1] = n & 0xff;
		e.banTime[2] = tm->tm_mon + 1;
		e.banTime[3] = tm->tm_mday;
		e.banTime[4] = tm->tm_hour; 
		e.banTime[5] = tm->tm_min;
		e.banTime[6] = tm->tm_sec;
		e.banTime[7] = *q - '0';
		n = utc_offset();
		if (n < 0) {
			e.banTime[8] = '-';
			n = - n;
		} else 
			e.banTime[8] = '+';
		e.banTime[9] = n / 60;
		e.banTime[10] = n % 60;
			
		while (*q && isdigit(*q))
			++q;
		while (*q && isspace(*q))
			++q;
		e.banRefCount = strtoul(q, &q, 10);
		
		while (*q && isspace(*q))
			++q;
		
		e.banExpression_len = strcspn(q, "\n");
		e.banExpression = malloc(e.banExpression_len);
		if (!e.banExpression) {
			vcli_disconnect(&conn);
			free(e.banTime);
			snmp_log(LOG_ERR, "out of memory\n");
			return SNMP_ERR_GENERR;
		}
		memcpy(e.banExpression, q, e.banExpression_len);
		
		create_entry(table, idx, &e);
		++idx;
		q += e.banExpression_len;
		p = q;
	}
	vcli_disconnect(&conn);
	DEBUGMSGTL(("varnish_ban", "loaded %ld ban entries", idx));
	return 0;
}

void
banTable_free(netsnmp_cache *cache, void *vmagic)
{
	netsnmp_tdata  *table = (netsnmp_tdata *) vmagic;
	netsnmp_tdata_row *row;

	DEBUGMSGTL(("varnish_ban", "freeing ban table"));
	while ((row = netsnmp_tdata_row_first(table))) {
		struct banTable_entry *entry = row->data;
		free(entry->banExpression);
		free(entry->banTime);
		SNMP_FREE(entry);
		netsnmp_tdata_remove_and_delete_row(table, row);
	}
}
