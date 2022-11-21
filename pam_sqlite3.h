/*
 * pam_sqlite - sqlite database pam module
 *
 * Copyright (C) 2022 A.Forouzan and A.Parker
 *
 * This file is part of pam_sqlite
 *
 * pam_sqlite is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License v3 as published by the
 * Free Software Foundation.
 *
 * pam_sqlite is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef PAM_SQLITE3_PAM_SQLITE3_H
#define PAM_SQLITE3_PAM_SQLITE3_H

#include "stdio.h"

#include "config.h"
#include <syslog.h>

#define MAX_ZSQL (-1)
#define FAIL(MSG) 		                                        \
	{ 					                        \
		SYSLOGERR(MSG);	                                        \
		free(buf);                                              \
		return NULL; 	                                        \
	}
#define GROW(x)                                                         \
	if ((x) > buflen - dest - 1) {       		                \
		char *grow;                            	                \
		buflen += 256 + (x);                          	        \
		grow = realloc(buf, buflen + 256 + (x));    	        \
		if (grow == NULL) FAIL("Out of memory building query"); \
		buf = grow;                              	        \
	}
#define DBGLOG(x...)                                                    \
	if(options->debug) {				                \
		openlog("PAM_sqlite3", LOG_PID, LOG_AUTH);              \
		syslog(LOG_DEBUG, ##x);					\
		closelog();                                             \
        }
#define SYSLOG(x...)                                                    \
	do {						                \
		openlog("PAM_sqlite3", LOG_PID, LOG_AUTH);              \
		syslog(LOG_INFO, ##x);					\
		closelog();                                             \
        } while(0)
#define SYSLOGERR(x...) SYSLOG("Error: " x)

typedef enum {
	PW_CLEAR = 1,
#if HAVE_SHA256_CRYPT
	PW_SHA256,
#endif
#if HAVE_SHA512_CRYPT
	PW_SHA512,
#endif
#if HAVE_MD5_CRYPT
	PW_MD5,
#endif
	PW_CRYPT,
} passwd_scheme;

struct module_options {
	char *database;
	char *table;
	char *user_column;
	char *passwd_column;
	char *passwd_type_column;
	char *expired_column;
	char *newtok_column;
	passwd_scheme default_passwd_type;
	int debug;
	char *sql_verify;
	char *sql_check_expired;
	char *sql_check_newtok;
	char *sql_set_passwd;
};

void memzero_explicit(void *s, size_t cnt);
const char* pam_get_service(pam_handle_t *pamh, const char **service);

#endif //PAM_SQLITE3_PAM_SQLITE3_H
