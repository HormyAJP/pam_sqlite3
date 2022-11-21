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

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <security/pam_modules.h>

#include "pam_sqlite3.h"
#include "pam_sqlite3_db.h"
#include "pam_sqlite3_password.h"

/* private: generate random salt character */
static char *
crypt_make_salt(passwd_scheme passwd_type)
{
	int i;
	time_t now;
	static unsigned long x;
	static char result[22];
	static char salt_chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";
	static const int NUM_SALT_CHARS = sizeof(salt_chars) / sizeof(salt_chars[0]);

	time(&now);
	x += now + getpid() + clock();
	srandom(x);

	for (i=0; i<19; i++) {
		result[i] = salt_chars[random() % NUM_SALT_CHARS];
	}
	result[i+1] = '$';
	result[i+2]='\0';

	switch(passwd_type) {
	case PW_CRYPT:
		result[2] = '\0';
		break;
#if HAVE_MD5_CRYPT
	case PW_MD5:
		result[0]='$';
		result[1]='1';
		result[2]='$';
		break;
#endif
#if HAVE_SHA256_CRYPT
	case PW_SHA256:
		result[0]='$';
		result[1]='5';
		result[2]='$';
		break;
#endif
#if HAVE_SHA512_CRYPT
	case PW_SHA512:
		result[0]='$';
		result[1]='6';
		result[2]='$';
		break;
#endif
	default:
		result[0] = '\0';
	}

	return result;
}

/* private: encrypt password using the preferred encryption scheme */
char *
encrypt_passwd(passwd_scheme passwd_type, const char *pass)
{
	char *s = NULL;

	switch(passwd_type) {
#if HAVE_MD5_CRYPT
	case PW_MD5:
#endif
#if HAVE_SHA256_CRYPT
	case PW_SHA256:
#endif
#if HAVE_SHA512_CRYPT
	case PW_SHA512:
#endif
	case PW_CRYPT:
		s = strdup(crypt(pass, crypt_make_salt(passwd_type)));
		break;
	case PW_CLEAR:
	default:
		s = strdup(pass);
	}

	return s;
}

/* private: authenticate user and passwd against database */
int
auth_verify_passwd(const char *username, const char *passwd,
		   struct module_options *options)
{
	int rc = PAM_AUTH_ERR;
	passwd_scheme stored_passwd_type;
	char *stored_passwd, *encrypted_passwd = NULL;

	if (!username || !passwd)
		return PAM_AUTH_ERR;

	if (db_get_passwd_info(username, passwd, options,
				 &stored_passwd, &stored_passwd_type) != PAM_INCOMPLETE)
		return PAM_AUTH_ERR;

	switch(stored_passwd_type) {
#if HAVE_MD5_CRYPT
	case PW_MD5:
#endif
#if HAVE_SHA256_CRYPT
	case PW_SHA256:
#endif
#if HAVE_SHA512_CRYPT
	case PW_SHA512:
#endif
	case PW_CRYPT:
		encrypted_passwd = crypt(passwd, stored_passwd);
		if (!encrypted_passwd) {
			SYSLOG("crypt failed when encrypting password");
			rc = PAM_AUTH_ERR;
		}

		if(strcmp(encrypted_passwd, stored_passwd) == 0)
			rc = PAM_SUCCESS;

		SYSLOG("enc_pass:%s", encrypted_passwd);
		SYSLOG("stored_pass:%s", stored_passwd);
		break;

	case PW_CLEAR:
	default:
		if(strcmp(passwd, stored_passwd) == 0)
			rc = PAM_SUCCESS;
		break;
	}

	free(stored_passwd);

	return rc;
}