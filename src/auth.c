/* This file is part of varnish-mib -*- c -*-
   Copyright (C) 2014-2015 Sergey Poznyakoff

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
#include "sha256.h"
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <errno.h>

void
varnish_auth_response_fd(int fd, const char *challenge,
			 char response[CLI_AUTH_RESPONSE_LEN + 1])
{
	struct sha256_ctx ctx;
	uint8_t buf[BUFSIZ];
	int i;

	assert(CLI_AUTH_RESPONSE_LEN == (SHA256_DIGEST_SIZE * 2));

	sha256_init_ctx(&ctx);
	sha256_process_bytes(challenge, 32, &ctx);
	sha256_process_bytes("\n", 1, &ctx);
	do {
		i = read(fd, buf, sizeof buf);
		if (i > 0)
			sha256_process_bytes(buf, i, &ctx);
	} while (i > 0);
	sha256_process_bytes(challenge, 32, &ctx);
 	sha256_process_bytes("\n", 1, &ctx);
	sha256_finish_ctx(&ctx, buf);
	for (i = 0; i < SHA256_DIGEST_SIZE; i++)
		sprintf(response + 2 * i, "%02x", buf[i]);
}

int
varnish_auth_response(const char *file, const char *challenge,
		      char response[CLI_AUTH_RESPONSE_LEN + 1])
{
	int fd = open(file, O_RDONLY);
	if (fd == -1) {
		snmp_log(LOG_ERR, "can't open secret file %s: %s\n",
			 file, strerror(errno));
		return -1;
	}
	varnish_auth_response_fd(fd, challenge, response);
	close(fd);
	return 0;
}
