/* This file is part of varnish-mib
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
#include <arpa/inet.h>

unsigned backendTable_timeout = 5;

void
varnish_backend_table_timeout_parser(const char *token, char *line)
{
	varnish_mib_timeout_parser(token, line, &backendTable_timeout);
}

/*
 * create a new row in the table 
 */
static struct backendTable_entry *
create_entry(netsnmp_tdata *table_data, long idx,
	     struct backendTable_entry *ent)
{
	struct backendTable_entry *entry;
	netsnmp_tdata_row *row;

	entry = SNMP_MALLOC_TYPEDEF(struct backendTable_entry);
	if (!entry)
		return NULL;
	
	row = netsnmp_tdata_create_row();
	if (!row) {
		SNMP_FREE(entry);
		return NULL;
	}
	row->data = entry;
	*entry = *ent;
	
	entry->vbeIndex = idx;
	netsnmp_tdata_row_add_index(row, ASN_INTEGER,
				    &entry->vbeIndex,
				    sizeof(entry->vbeIndex));
	if (table_data)
		netsnmp_tdata_add_row(table_data, row);
	return entry;
}

#define VSC_POINT_TYPE(p) ((p)->section->fantom->type)
#define VSC_POINT_IDENT(p) ((p)->section->fantom->ident)
#define VSC_POINT_NAME(p) ((p)->desc->name)
#define VSC_POINT_FMT(p) ((p)->desc->fmt)

struct betab_priv {
	int err;
	long idx;
	struct backendTable_entry ent;
	netsnmp_tdata  *table;
};

struct betab_trans {
	const char *name;
	size_t off;
};

static struct betab_trans betab_trans[] = {
	{ "vcls",
	  offsetof(struct backendTable_entry, vbeVcls) },
	{ "happy",
	  offsetof(struct backendTable_entry, vbeHappyProbes) },               
	{ "bereq_hdrbytes",
	  offsetof(struct backendTable_entry, vbeRequestHeaderBytes) },    
	{ "bereq_bodybytes",
	  offsetof(struct backendTable_entry, vbeRequestBodyBytes) },      
	{ "beresp_hdrbytes",
	  offsetof(struct backendTable_entry, vbeResponseHeaderBytes) },      
	{ "beresp_bodybytes",
	  offsetof(struct backendTable_entry, vbeResponseBodyBytes) },     
	{ "pipe_hdrbytes",
	  offsetof(struct backendTable_entry, vbePipeHeaderBytes) },
	{ "pipe_in",
	  offsetof(struct backendTable_entry, vbePipeIn) },
	{ "pipe_out",
	  offsetof(struct backendTable_entry, vbePipeOut) },
	{ NULL }
};

static int
identcmp(struct betab_priv *bp, const char *ident)
{
	size_t len;
	size_t i;
	
	if (bp->idx == -1)
		return 1;
	for (i = 0; i < bp->ent.vbeIdent_len; i++, ident++)
		if (bp->ent.vbeIdent[i] != *ident)
			return 1;
	if (*ident == '(' || *ident == 0)
		return 0;
	return 1;
}

static void
uint32_to_bytes (unsigned char *bytes, uint32_t u)
{
  int i;

  for (i = 0; i < 4; i++)
    {
      bytes[i] = u & 0xff;
      u >>= 8;
    }
}

static void
scanbuf(const char *s, struct backendTable_entry *ent)
{
	char ipv4buf[16];
	char ipv6buf[81];
	unsigned long port;
	char *p;
	union {
		struct in_addr in;
		struct in6_addr in6;
	} v;
	
	if (*s != '(')
		return;
	++s;
	p = ipv4buf;
	while (p < ipv4buf + sizeof(ipv4buf) && *s && *s != ',')
		*p++ = *s++;
	if (*s != ',')
		return;
	*p = 0;

	++s;
	p = ipv6buf;
	while (p < ipv6buf + sizeof(ipv6buf) && *s && *s != ',')
		*p++ = *s++;
	*p = 0;

	++s;
	port = strtoul(s, &p, 10);
	if (*p != ')' || port > USHRT_MAX)
		return;

	if (ipv4buf[0] && inet_pton(AF_INET, ipv4buf, &v)) {
		ent->vbeIPv4_len = 4;
		uint32_to_bytes(ent->vbeIPv4, v.in.s_addr);
	}

	if (ipv6buf[0] && inet_pton(AF_INET6, ipv6buf, &v)) {
		ent->vbeIPv6_len = 16;
		memcpy(ent->vbeIPv6, &v, ent->vbeIPv6_len);
	}
	ent->vbePort = port;
}		
	
/* Process a single statistics point.  See comment below. */
static int
create_entry_cb(void *priv, const struct VSC_point *const pt)
{
	struct betab_priv *bp = priv;
	struct betab_trans *tp;

	if (bp->err || !pt || strcmp(VSC_POINT_TYPE(pt), "VBE") ||
	    strcmp(VSC_POINT_FMT(pt), "uint64_t"))
		return 0;
	if (identcmp(bp, VSC_POINT_IDENT(pt))) {
		const char *full_id;
		
		if (bp->idx != -1
		    && !create_entry(bp->table, bp->idx, &bp->ent)) {
			snmp_log(LOG_ERR, "out of memory\n");
			bp->err = SNMP_ERR_GENERR;
			return 0;
		}

		memset(&bp->ent, 0, sizeof(bp->ent));
		bp->ent.vbeIndex = ++bp->idx;

		full_id = VSC_POINT_IDENT(pt);
		bp->ent.vbeIdent_len = strcspn(full_id, "(");
		bp->ent.vbeIdent = malloc(bp->ent.vbeIdent_len);
		if (!bp->ent.vbeIdent) {
			snmp_log(LOG_ERR, "out of memory\n");
			bp->err = SNMP_ERR_GENERR;
                        return 0;
		}
		memcpy(bp->ent.vbeIdent, full_id, bp->ent.vbeIdent_len);
		full_id += bp->ent.vbeIdent_len;
		scanbuf(full_id, &bp->ent);
	}

	for (tp = betab_trans; tp->name; tp++) {
		if (strcmp(VSC_POINT_NAME(pt), tp->name) == 0) {
			U64 *u = (U64*)((char*)&bp->ent + tp->off);
			uint64_t n = *(const volatile uint64_t*)pt->ptr;
			u->high = n >> 32;
			u->low = n & 0xffffffff;
			break;
		}
	}
	return 0;
}

/* Varnish API does not provide access to struct VSC_C_vbe, so the only
   way to backend statistics is to iterate over all statistics data, selecting
   the entries marked as VBE.  That's what this function does. 
 */
int
backendTable_load(netsnmp_cache *cache, void *vmagic)
{
	struct VSM_data *vd = varnish_get_vsm_data();
	struct betab_priv bp;

	bp.idx = -1;
	bp.err = 0;
	bp.table = (netsnmp_tdata *) vmagic;
	memset(&bp.ent, 0, sizeof(bp.ent));

	DEBUGMSGTL(("varnish_ban", "loading backend table"));
	VSC_Iter(vd, NULL, create_entry_cb, &bp);
	/* FIXME: perhaps handle bp.err separately */
	if (bp.idx != -1) {
		DEBUGMSGTL(("varnish_ban", "loaded %lu backend entries",
			    bp.idx + 1));
		if (!create_entry(bp.table, bp.idx, &bp.ent))
			snmp_log(LOG_ERR, "out of memory\n");
	}
	return 0;
}

void
backendTable_free(netsnmp_cache *cache, void *vmagic)
{
	netsnmp_tdata  *table = (netsnmp_tdata *) vmagic;
	netsnmp_tdata_row *row;

	DEBUGMSGTL(("varnish_ban", "freeing backend table"));
	while ((row = netsnmp_tdata_row_first(table))) {
		struct backendTable_entry *entry = row->data;
		free(entry->vbeIdent);
		SNMP_FREE(entry);
		netsnmp_tdata_remove_and_delete_row(table, row);
	}
}
