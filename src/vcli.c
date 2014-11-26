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
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>

#define ISSPACE(c) ((c)==' '||(c)=='\t'||(c)=='\n')

static unsigned vcli_timeout = 5;

void
varnish_vcli_timeout_parser(const char *token, char *line)
{
	varnish_mib_timeout_parser(token, line, &vcli_timeout);
}

#define VCLI_INIT_ALLOC 16

static int
vcli_alloc(struct vcli_conn *conn, size_t size)
{
	char *p;

	if (size < conn->bufmax)
		return 0;
	p = realloc(conn->base, size);
	if (!p) {
		snmp_log(LOG_ERR, "out of memory\n");
		return -1;
	}
	conn->base = p;
	conn->bufmax = size;
	return 0;
}
	
static int
vcli_extra_size(struct vcli_conn *conn, size_t incr)
{
	if (incr + conn->bufsize > conn->bufmax) {
		size_t size;
		if (conn->bufmax == 0)
			size = incr > VCLI_INIT_ALLOC
				? incr
				: VCLI_INIT_ALLOC;
		else {
			for (size = conn->bufmax; size < conn->bufsize + incr;
			     size *= 2)
				if (size <= conn->bufmax) {
					snmp_log(LOG_ERR, "out of memory\n");
					return -1;
				}
		}
		return vcli_alloc(conn, size);
	}
	return 0;
}

static int
vcli_read(struct vcli_conn *conn, size_t size)
{
	fd_set rd;
	time_t start;
	struct timeval tv;
	long ttl;
	int ret = 0;
	int rc;
	
	++size;
	rc = vcli_alloc(conn, size + 1);
	if (rc)
		return SNMP_ERR_GENERR;

	conn->bufsize = 0;
	time(&start);
	while (size) {
		FD_ZERO(&rd);
		FD_SET(conn->fd, &rd);
		
		ttl = vcli_timeout - (time(NULL) - start);
		if (ttl <= 0) {
			snmp_log(LOG_ERR, "timed out reading from varnish\n");
			ret = -1;
			break;
		}

		tv.tv_sec = ttl;
		tv.tv_usec = 0;
		rc = select(conn->fd + 1, &rd, NULL, NULL, &tv);
		if (rc < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			snmp_log(LOG_ERR, "select: %s\n", strerror(errno));
			ret = -1;
			break;
		}

		if (FD_ISSET(conn->fd, &rd)) {
			int n;
			
			if (ioctl(conn->fd, FIONREAD, &n) < 0) {
				snmp_log(LOG_ERR, "ioctl: %s\n",
					 strerror(errno));
				ret = -1;
				break;
			}
			if (n > size)
				n = size;
			rc = read(conn->fd, conn->base + conn->bufsize, n);
			if (rc > 0) {
				conn->bufsize += rc;
				size -= rc;
			} else if (rc == 0
				   || errno == EINTR || errno == EAGAIN) {
				continue;
			} else {
				snmp_log(LOG_ERR, "read: %s\n",
					 strerror(errno));
				ret = -1;
				break;
			}
		}
	}

	if (ret == 0) {
		if (conn->bufsize == 0)
			ret = -1;
		conn->base[conn->bufsize] = 0;
		DEBUGMSGTL(("vcli_mib", "<<varnish: %s\n", conn->base));
	}
	
	return ret;
}

static int
vcli_getline(struct vcli_conn *conn)
{
	fd_set rd;
	time_t start;
	struct timeval tv;
	long ttl;
	int ret = 0;
	int rc;

	conn->bufsize = 0;
	time(&start);
	while (1) {
		FD_ZERO(&rd);
		FD_SET(conn->fd, &rd);
		
		ttl = vcli_timeout - (time(NULL) - start);
		if (ttl <= 0) {
			snmp_log(LOG_ERR, "timed out reading from varnish\n");
			ret = -1;
			break;
		}

		tv.tv_sec = ttl;
		tv.tv_usec = 0;
		rc = select(conn->fd + 1, &rd, NULL, NULL, &tv);
		if (rc < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			snmp_log(LOG_ERR, "select: %s\n", strerror(errno));
			ret = -1;
			break;
		}

		if (FD_ISSET(conn->fd, &rd)) {
			char c;

			rc = read(conn->fd, &c, 1);
			if (rc == 1) {
				if (vcli_extra_size(conn, 1)) {
					ret = -1;
					break;
				}
				conn->base[conn->bufsize++] = c;
				if (c == '\n')
					break;
			} else if (rc == 0
				   || errno == EINTR || errno == EAGAIN) {
				continue;
			} else {
				snmp_log(LOG_ERR, "read: %s\n",
					 strerror(errno));
				ret = -1;
				break;
			}
		}
	}

	if (ret == 0) {
		if (conn->bufsize == 0)
			ret = -1;
		else if (conn->base[conn->bufsize-1] == '\n') {
			conn->bufsize--;
			if (conn->base[conn->bufsize-1] == '\r')
				conn->bufsize--;
		}
		conn->base[conn->bufsize] = 0;
	}
	
	return ret;
}

int
vcli_write(struct vcli_conn *conn)
{
	size_t size;

	DEBUGMSGTL(("vcli_mib", ">>varnish: %s\n", conn->base));
	for (size = 0; size < conn->bufsize; ) {
		int n = write(conn->fd, conn->base + size,
			      conn->bufsize - size);
		if (n < 0) {
			snmp_log(LOG_ERR, "write error: %s\n",
				 strerror(errno));
			return -1;
		}
		size += n;
	}
	return 0;
}

int
vcli_read_response(struct vcli_conn *conn)
{
	char *p;
	unsigned long n;
	
	if (vcli_getline(conn)) {
		vcli_disconnect(conn);
		return SNMP_ERR_GENERR;
	}

	n = strtoul(conn->base, &p, 10);
	conn->resp = n;
	if (!ISSPACE(*p)) {
		snmp_log(LOG_ERR, "unrecognized response from Varnish: %s\n",
			 conn->base);
		return SNMP_ERR_GENERR;
	}
	while (*p && ISSPACE(*p))
		++p;
	n = strtoul(p, &p, 10);
	if (n > 0)
		return vcli_read(conn, n);
	return 0;
}

int
vcli_vasprintf(struct vcli_conn *conn, const char *fmt, va_list ap)
{
	int rc = 0;
  
	rc = vcli_alloc(conn, VCLI_INIT_ALLOC);
	if (rc)
		return -1;
  
	for (;;) {
		va_list aq;
		ssize_t n;

		va_copy(aq, ap);
		n = vsnprintf(conn->base, conn->bufmax, fmt, aq);
		va_end(aq);
		if (n < 0 || n >= conn->bufmax ||
		    !memchr(conn->base, '\0', n + 1)) {
			size_t newlen = conn->bufmax * 2;
			if (newlen < conn->bufmax) {
				snmp_log(LOG_ERR, "out of memory\n");
				rc = -1;
				break;
			}
			rc = vcli_alloc(conn, newlen);
			if (rc)
				break;
		} else {
			conn->bufsize = n;
			break;
		}
	}

	return rc;
}  

int
vcli_asprintf(struct vcli_conn *conn, const char *fmt, ...)
{
	int rc;
	va_list ap;
	
	va_start(ap, fmt);
	rc = vcli_vasprintf(conn, fmt, ap);
	va_end(ap);
	return rc;
}


static int
open_socket(struct sockaddr_in *sa, const char *connstr)
{
	int fd = socket(sa->sin_family, SOCK_STREAM, 0);
	struct timeval start, connect_tv;

	if (fd == -1) {
		snmp_log(LOG_ERR, "socket: %s\n", strerror(errno));
		return -1;
	}

	connect_tv.tv_sec = vcli_timeout;
	connect_tv.tv_usec = 0;
	
	gettimeofday(&start, NULL);
	for (;;) {
		int rc = connect(fd, sa, sizeof(*sa));
		if (rc == 0)
			break;
		else if (errno == ECONNREFUSED) {
			struct timeval tv, now;
			fd_set rset, wset, xset;
			
			gettimeofday(&now, NULL);
			timersub(&now, &start, &tv);
			
			if (timercmp(&tv, &connect_tv, < )) {
				FD_ZERO(&rset);
				FD_SET(fd, &rset);
				FD_ZERO(&wset);
				FD_SET(fd, &wset);
				FD_ZERO(&xset);
				FD_SET(fd, &xset);
				select(fd + 1, &rset, &wset, &xset, &tv);
				continue;
			}
		}

		snmp_log(LOG_ERR, "cannot connect to %s: %s\n",
			 connstr, strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}

void
vcli_disconnect(struct vcli_conn *conn)
{
	close(conn->fd);
	free(conn->base);
	free(conn->secret);
	memset(conn, 0, sizeof(*conn));
}

static int
vcli_handshake(struct vcli_conn *conn)
{
	if (vcli_read_response(conn))
		return 1;

	if (conn->resp == CLIS_AUTH) {
		char buf[CLI_AUTH_RESPONSE_LEN + 1];
		char *p = strchr(conn->base, '\n');

		if (!p) {
			snmp_log(LOG_ERR,
				 "unrecognized response from Varnish: %s\n",
				 conn->base);
			return SNMP_ERR_GENERR;
		}
		*p = 0;
		if (varnish_auth_response(conn->secret, conn->base, buf))
			return 1;
		
		if (vcli_asprintf(conn, "auth %s\n", buf) ||
		    vcli_write(conn))
			return 1;

		if (vcli_read_response(conn))
			return 1;
	}

	if (conn->resp != CLIS_OK) {
		snmp_log(LOG_ERR, "Varnish connection rejected: %u %s\n",
			 conn->resp, conn->base);
		return 1;
	}

	if (vcli_asprintf(conn, "ping\n") || vcli_write(conn))
		return 1;

	if (vcli_read_response(conn))
		return 1;

	if (conn->resp != CLIS_OK || strstr(conn->base, "PONG") == NULL) {
		snmp_log(LOG_ERR, "expected PONG, but got %s\n",
			 conn->base);
		return 1;
	}
	
	return 0;
}

int
vcli_connect(struct VSM_data *vd, struct vcli_conn *conn)
{
	struct VSM_fantom vt;
	struct sockaddr_in vcli_sa;
	char *s, *portstr, *p;
	unsigned long n;
	short pn;
	struct hostent *hp;

	memset(conn, 0, sizeof(*conn));
	
	if (!VSM_Get(vd, &vt, "Arg", "-T", "")) {
                snmp_log(LOG_ERR, "no -T arg in shared memory\n");
                return SNMP_ERR_GENERR;
        }
	DEBUGMSGTL(("vcli_mib", "-T '%s'\n", vt.b));
	
	s = strdup(vt.b);
	if (!s) {
                snmp_log(LOG_ERR, "out of memory\n");
		return SNMP_ERR_GENERR;
	}
	for (portstr = s; !ISSPACE(*portstr); portstr++)
		;
	if (!*portstr) {
                snmp_log(LOG_ERR, "unrecognized -T arg: %s\n", s);
		free(s);
		return SNMP_ERR_GENERR;
	}
	for (*portstr++ = 0; ISSPACE(*portstr); portstr++)
		;

	n = pn = strtoul(portstr, &p, 0);
	if (n != pn || (*p && !ISSPACE(*p))) {
                snmp_log(LOG_ERR, "unrecognized -T arg: %s\n", s);
		free(s);
		return SNMP_ERR_GENERR;
	}

	hp = gethostbyname(s);
	if (!hp) {
		snmp_log(LOG_ERR, "unknown host name %s\n", s);
		free(s);
		return SNMP_ERR_GENERR;
	}

	vcli_sa.sin_family = hp->h_addrtype;
	if (vcli_sa.sin_family != AF_INET) {
		snmp_log(LOG_ERR, "unknown host name %s\n", s);
		free(s);
		return SNMP_ERR_GENERR;
	}

	memmove(&vcli_sa.sin_addr, hp->h_addr, 4);
	vcli_sa.sin_port = htons(pn);

	conn->fd = open_socket(&vcli_sa, s);
	free(s);
	if (conn->fd == -1)
		return SNMP_ERR_GENERR;

	if (!VSM_Get(vd, &vt, "Arg", "-S", "")) {
                snmp_log(LOG_ERR, "no -S arg in shared memory\n");
                return SNMP_ERR_GENERR;
        }
	DEBUGMSGTL(("vcli_mib", "-S '%s'\n", vt.b));
	s = strdup(vt.b);
	if (!s) {
                snmp_log(LOG_ERR, "out of memory\n");
		return SNMP_ERR_GENERR;
	}
	conn->secret = s;

	if (vcli_handshake(conn)) {
		vcli_disconnect(conn);
		return SNMP_ERR_GENERR;
	}
	return SNMP_ERR_NOERROR;
}
