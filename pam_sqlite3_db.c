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

#include <stdlib.h>
#include <string.h>
#include <security/pam_modules.h>

#include "pam_sqlite3_db.h"

#define APPEND(str, len)	GROW(len); memcpy(buf + dest, str, len); dest += len
#define APPENDS(str)	        len = strlen(str); APPEND(str, len)
/*
 * Being very defensive here. The current logic in the rest of the code should prevent this from
 * happening. But lets protect against future code changes which could cause a NULL ptr to creep
 * in.
 */
#define CHECK_STRING(str) 													 	\
	if (!(str)) 															    	\
		FAIL("Internal error in format_query: string ptr " #str " was NULL");

/* private: open SQLite database */
sqlite3 *pam_sqlite3_connect(struct module_options *options)
{
	const char *errtext = NULL;
	sqlite3 *sdb = NULL;

	if (sqlite3_open(options->database, &sdb) != SQLITE_OK) {
		errtext = sqlite3_errmsg(sdb);
		SYSLOG("Error opening SQLite database (%s)", errtext);
		/*
		 * N.B. sdb is usually non-NULL when errors occur, so we explicitly
		 * release the resource and return NULL to indicate failure to the caller.
		 */

		sqlite3_close(sdb);
		return NULL;
	}

	return sdb;
}

char *format_query(const char *template, struct module_options *options,
		   const char *user, const char *passwd)
{
	char *buf = malloc(256);
	if (!buf)
		return NULL;

	int buflen = 256;
	int dest = 0, len;
	const char *src = template;
	char *pct;
	char *tmp;

	while (*src) {
		pct = strchr(src, '%');

		if (pct) {
			/* copy from current position to % char into buffer */
			if (pct != src) {
				len = pct - src;
				APPEND(src, len);
			}

			/* decode the escape */
			switch(pct[1]) {
				case 'U':	/* username */
					if (user) {
						tmp = sqlite3_mprintf("%q", user);
						if (!tmp)
							FAIL("sqlite3_mprintf out of memory");
						len = strlen(tmp);
						APPEND(tmp, len);
						sqlite3_free(tmp);
					}
					break;
				case 'P':	/* password */
					if (passwd) {
						tmp = sqlite3_mprintf("%q", passwd);
						if (!tmp)
							FAIL("sqlite3_mprintf out of memory");
						len = strlen(tmp);
						APPEND(tmp, len);
						sqlite3_free(tmp);
					}
					break;

				case 'O':	/* option value */
					pct++;
					switch (pct[1]) {
						case 'p':	/* passwd */
							CHECK_STRING(options->passwd_column);
							APPENDS(options->passwd_column);
							break;
						case 'k':	/* passwd type */
							CHECK_STRING(options->passwd_type_column);
							APPENDS(options->passwd_type_column);
							break;
						case 'u':	/* username */
							CHECK_STRING(options->user_column);
							APPENDS(options->user_column);
							break;
						case 't':	/* table */
							CHECK_STRING(options->table);
							APPENDS(options->table);
							break;
						case 'x':	/* expired */
							CHECK_STRING(options->expired_column);
							APPENDS(options->expired_column);
							break;
						case 'n':	/* newtok */
							CHECK_STRING(options->newtok_column);
							APPENDS(options->newtok_column);
							break;
					}
					break;

				case '%':	/* quoted % sign */
					APPEND(pct, 1);
					break;

				default:	/* unknown */
					APPEND(pct, 2);
					break;
			}
			src = pct + 2;
		} else {
			/* copy rest of string into buffer and we're done */
			len = strlen(src);
			APPEND(src, len);
			break;
		}
	}

	buf[dest] = '\0';
	return buf;
}

/* private: authenticate user and passwd against database */
int
db_get_passwd_info(const char *user, const char *passwd,
                    struct module_options *options,
		    char **stored_passwd, passwd_scheme *stored_passwd_type)
{
	int res, rc = PAM_AUTH_ERR;
	sqlite3 *conn = NULL;
	sqlite3_stmt *vm = NULL;
	char *query  = NULL;
	const char *tail  = NULL, *errtext = NULL;

	*stored_passwd = NULL;
	*stored_passwd_type = PW_CLEAR;

	if(!(conn = pam_sqlite3_connect(options))) {
		rc = PAM_AUTH_ERR;
		goto done;
	}

	if(!(query = format_query(options->sql_verify ? options->sql_verify :
	                          "SELECT %Op, %Ok FROM %Ot WHERE %Ou='%U'",
	                          options, user, passwd))) {
		SYSLOGERR("failed to construct sql query");
		rc = PAM_AUTH_ERR;
		goto done;
	}

	DBGLOG("query: %s", query);

	res = sqlite3_prepare(conn, query, MAX_ZSQL, &vm, &tail);

	free(query);

	if (res != SQLITE_OK) {
		errtext = sqlite3_errmsg(conn);
		DBGLOG("Error executing SQLite query (%s)", errtext);
		rc = PAM_AUTH_ERR;
		goto done;
	}

	if (SQLITE_ROW != sqlite3_step(vm)) {
		rc = PAM_USER_UNKNOWN;
		DBGLOG("no rows to retrieve");
	} else {
		*stored_passwd = (char *) sqlite3_column_text(vm, 0);
		if (!(*stored_passwd)) {
			SYSLOG("sqlite3 failed to return row data");
			rc = PAM_AUTH_ERR;
			goto done;
		}
		else
			*stored_passwd = strdup(*stored_passwd);

		*stored_passwd_type = sqlite3_column_int(vm, 1);
		if (!*stored_passwd_type)
			*stored_passwd_type = PW_CLEAR;

		DBGLOG("passwd type: %d", *stored_passwd_type);

		rc = PAM_INCOMPLETE;
	}

done:
	sqlite3_finalize(vm);
	sqlite3_close(conn);

	return rc;
}