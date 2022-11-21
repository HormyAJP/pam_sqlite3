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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sqlite3.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_CRYPT_H
#include <crypt.h>
#endif

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_PASSWORD
#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include "pam_mod_misc.h"

#include "config.h"
#include "pam_sqlite3_password.h"
#include "pam_sqlite3_conversation.h"
#include "pam_sqlite3_db.h"
#include "pam_sqlite3.h"

#define PASSWORD_PROMPT			"Password: "
#define PASSWORD_PROMPT_NEW		"New password: "
#define PASSWORD_PROMPT_CONFIRM         "Confirm new password: "
#define PASSWORD_PROMPT_TYPE            "Password type (1: plane, 2: MD5, 3: SHA256, 4: SHA512, 5: ENCRYPTED):"
#define CONFIG_FILE_PATH		"/etc/pam_sqlite3.conf"
#define UNKNOWN_SERVICE                 "<Unknown Service>"

/*
 * safe_assign protects against duplicate config options causing a memory leak.
 */
static void inline
safe_assign(char **asignee, const char *val)
{
	if(*asignee)
		free(*asignee);
	*asignee = strdup(val);
}

void memzero_explicit(void *s, size_t cnt)
{
	memset(s, 0, cnt);
	__asm__ __volatile__("": :"r"(s): "memory");
}

const char* pam_get_service(pam_handle_t *pamh, const char **service)
{
	if (pam_get_item(pamh, PAM_SERVICE, (const void**)service) != PAM_SUCCESS)
		*service = UNKNOWN_SERVICE;
	return *service;
}

static void
get_module_options_from_file(const char *filename, struct module_options *opts, int warn);

/* private: parse and set the specified string option */
static void
set_module_option(const char *option, struct module_options *options)
{
	char *buf, *eq;
	char *val, *end;

	if(!option || !*option)
		return;

	buf = strdup(option);
	if(!buf)
		return;

	if((eq = strchr(buf, '='))) {
		end = eq - 1;
		val = eq + 1;
		if(end <= buf || !*val)
		{
			free(buf);
			return;
		}
		while(end > buf && isspace(*end))
			end--;
		end++;
		*end = '\0';
		while(*val && isspace(*val))
			val++;
	} else {
		val = NULL;
	}

	DBGLOG("setting option: %s=>%s\n", buf, val);

	if(!strcmp(buf, "database")) {
		safe_assign(&options->database, val);
	} else if(!strcmp(buf, "table")) {
		safe_assign(&options->table, val);
	} else if(!strcmp(buf, "user_column")) {
		safe_assign(&options->user_column, val);
	} else if(!strcmp(buf, "pwd_column")) {
		safe_assign(&options->passwd_column, val);
	} else if(!strcmp(buf, "pwd_type_column")) {
		safe_assign(&options->passwd_type_column, val);
	} else if(!strcmp(buf, "expired_column")) {
		safe_assign(&options->expired_column, val);
	} else if(!strcmp(buf, "newtok_column")) {
		safe_assign(&options->newtok_column, val);
	} else if(!strcmp(buf, "default_pw_type")) {
		options->default_passwd_type = PW_CLEAR;
		if(!strcmp(val, "crypt")) {
			options->default_passwd_type = PW_CRYPT;
		}
#if HAVE_MD5_CRYPT
		else if(!strcmp(val, "md5")) {
			options->default_passwd_type = PW_MD5;
		}
#endif
#if HAVE_SHA256_CRYPT
		else if(!strcmp(val, "sha-256")) {
			options->default_passwd_type = PW_SHA256;
		}
#endif
#if HAVE_SHA512_CRYPT
		else if(!strcmp(val, "sha-512")) {
			options->default_passwd_type = PW_SHA512;
		}
#endif
	} else if(!strcmp(buf, "debug")) {
		options->debug = 1;
	} else if (!strcmp(buf, "config_file")) {
		get_module_options_from_file(val, options, 1);
	} else if (!strcmp(buf, "sql_verify")) {
		safe_assign(&options->sql_verify, val);
	} else if (!strcmp(buf, "sql_check_expired")) {
		safe_assign(&options->sql_check_expired, val);
	} else if (!strcmp(buf, "sql_check_newtok")) {
		safe_assign(&options->sql_check_newtok, val);
	} else if (!strcmp(buf, "sql_set_passwd")) {
		safe_assign(&options->sql_set_passwd, val);
	} else {
		DBGLOG("ignored option: %s\n", buf);
	}

	free(buf);
}

/* private: read module options from a config file */
static void
get_module_options_from_file(const char *filename, struct module_options *opts, int warn)
{
	FILE *fp;

	if ((fp = fopen(filename, "r"))) {
		char line[1024];
		char *str, *end;

		while(fgets(line, sizeof(line), fp)) {
			str = line;
			end = line + strlen(line) - 1;
			while(*str && isspace(*str))
				str++;
			while(end > str && isspace(*end))
				end--;
			end++;
			*end = '\0';
			set_module_option(str, opts);
		}
		fclose(fp);
	} else if (warn) {
		SYSLOG("unable to read config file %s", filename);
	}
}

/*
 * If the given name is a standard option, set the corresponding flag in
 * the options word and return 0.  Else return -1.
 */
static int
pam_std_option(int *options, const char *name)
{
	struct opttab {
		const char *name;
		int value;
	};
	static struct opttab std_options[] = {
		{ "debug",          PAM_OPT_DEBUG },
		{ "no_warn",        PAM_OPT_NO_WARN },
		{ "use_first_pass", PAM_OPT_USE_FIRST_PASS },
		{ "try_first_pass", PAM_OPT_TRY_FIRST_PASS },
		{ "use_mapped_pass",PAM_OPT_USE_MAPPED_PASS },
		{ "echo_pass",      PAM_OPT_ECHO_PASS },
		{ NULL,         0 }
	};
	struct opttab *p;

	for (p = std_options;  p->name != NULL;  p++) {
		if (strcmp(name, p->name) == 0) {
			*options |= p->value;
			return 0;
		}
	}
	return -1;
}

/* private: read module options from file or commandline */
static int
get_module_options(int argc, const char **argv, struct module_options **options)
{
	int i, rc;
	struct module_options *opts;

	rc = 0;
	if (!(opts = (struct module_options *)malloc(sizeof *opts))){
		*options = NULL;
		return rc;
	}

	bzero(opts, sizeof(*opts));
	opts->default_passwd_type = PW_CLEAR;

	get_module_options_from_file(CONFIG_FILE_PATH, opts, 0);

	for(i = 0; i < argc; i++) {
		if(pam_std_option(&rc, argv[i]) == 0)
			continue;
		set_module_option(argv[i], opts);
	}
	*options = opts;

	return rc;
}

/* private: free module options returned by get_module_options() */
static void
free_module_options(struct module_options *options)
{
	if (!options)
		return;

	if(options->database)
		free(options->database);
	if(options->table)
		free(options->table);
	if(options->user_column)
		free(options->user_column);
	if(options->passwd_column)
		free(options->passwd_column);
	if(options->expired_column)
		free(options->expired_column);
	if(options->newtok_column)
		free(options->newtok_column);
	if(options->sql_verify)
		free(options->sql_verify);
	if(options->sql_check_expired)
		free(options->sql_check_expired);
	if(options->sql_check_newtok)
		free(options->sql_check_newtok);
	if(options->sql_set_passwd)
		free(options->sql_set_passwd);

	bzero(options, sizeof(*options));
	free(options);
}

/* private: make sure required options are present (in cmdline or conf file) */
static int
options_valid(struct module_options *options)
{
	if(!options)
	{
		SYSLOGERR("failed to read options.");
		return -1;
	}

	if(options->database == 0 || options->table == 0 || options->user_column == 0)
	{
		SYSLOGERR("the database, table and user_column options are required.");
		return -1;
	}
	return 0;
}

/* public: authenticate user */
PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	struct module_options *options = NULL;
	const char *user = NULL, *passwd = NULL, *service = NULL;
	int rc, std_flags;

	std_flags = get_module_options(argc, argv, &options);
	if(options_valid(options) != 0) {
		rc = PAM_AUTH_ERR;
		goto done;
	}

	if((rc = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS) {
		SYSLOG("failed to get username from pam");
		goto done;
	}

	DBGLOG("attempting to authenticate: %s", user);

	if((rc = pam_get_pass(pamh, &passwd, PASSWORD_PROMPT, std_flags)
		!= PAM_SUCCESS)) {
		goto done;
	}

	if((rc = auth_verify_passwd(user, passwd, options)) != PAM_SUCCESS)
		SYSLOG("(%s) user %s not authenticated.", pam_get_service(pamh, &service), user);
	else
		SYSLOG("(%s) user %s authenticated.", pam_get_service(pamh, &service), user);

done:
	free_module_options(options);
	return rc;
}

/* public: check if account has expired, or needs new password */
PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc,
							const char **argv)
{
	struct module_options *options = NULL;
	const char *user = NULL;
	int rc = PAM_AUTH_ERR;
	sqlite3 *conn = NULL;
	sqlite3_stmt *vm = NULL;
	char *query = NULL;
	const char *tail = NULL;
	const char *errtext = NULL;
	int res;

	get_module_options(argc, argv, &options);
	if(options_valid(options) != 0) {
		rc = PAM_AUTH_ERR;
		goto done;
	}

	/* both not specified, just succeed. */
	if(options->expired_column == NULL && options->newtok_column == NULL) {
		rc = PAM_SUCCESS;
		goto done;
	}

	if((rc = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS) {
		SYSLOGERR("could not retrieve user");
		goto done;
	}

	if(!(conn = pam_sqlite3_connect(options))) {
		SYSLOGERR("could not connect to database");
		rc = PAM_AUTH_ERR;
		goto done;
	}

	/* if account has expired then expired_column = '1' or 'y' */
	if(options->expired_column || options->sql_check_expired) {

		if(!(query = format_query(options->sql_check_expired ? options->sql_check_expired :
				"SELECT 1 from %Ot WHERE %Ou='%U' AND (%Ox='y' OR %Ox='1')",
				options, user, NULL))) {
			SYSLOGERR("failed to construct sql query");
			rc = PAM_AUTH_ERR;
			goto done;
		}

		DBGLOG("query: %s", query);

		res = sqlite3_prepare(conn, query, MAX_ZSQL, &vm, &tail);

		free(query);

		if (res != SQLITE_OK) {
            errtext = sqlite3_errmsg(conn);
			SYSLOGERR("Error executing SQLite query (%s)", errtext);
			rc = PAM_AUTH_ERR;
			goto done;
		}

		res = sqlite3_step(vm);

		DBGLOG("query result: %d", res);

		if(SQLITE_ROW == res) {
			rc = PAM_ACCT_EXPIRED;
			goto done;
		}
		sqlite3_finalize(vm);
		vm = NULL;
	}

	/* if new password is required then newtok_column = 'y' or '1' */
	if(options->newtok_column || options->sql_check_newtok) {
		if(!(query = format_query(options->sql_check_newtok ? options->sql_check_newtok :
				"SELECT 1 FROM %Ot WHERE %Ou='%U' AND (%On='y' OR %On='1')",
				options, user, NULL))) {
			SYSLOGERR("failed to construct sql query");
			rc = PAM_AUTH_ERR;
			goto done;
		}

		DBGLOG("query: %s", query);

		res = sqlite3_prepare(conn, query, MAX_ZSQL, &vm, &tail);
		free(query);

		if (res != SQLITE_OK) {
            errtext = sqlite3_errmsg(conn);
			SYSLOGERR("query failed: %s", errtext);
			rc = PAM_AUTH_ERR;
			goto done;
		}

		res = sqlite3_step(vm);

		if(SQLITE_ROW == res) {
			rc = PAM_NEW_AUTHTOK_REQD;
			goto done;
		}
		sqlite3_finalize(vm);
		vm = NULL;
	}

	rc = PAM_SUCCESS;

done:
	/* Do all cleanup in one place. */
	sqlite3_finalize(vm);
	sqlite3_close(conn);
	free_module_options(options);
	return rc;
}

/* public: change password */
PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	struct module_options *options = NULL;
	int rc = PAM_AUTH_ERR;
	int std_flags;
	const char *user = NULL, *pass = NULL, *newpass = NULL, *service = NULL;
	char *newpass_crypt = NULL, *pass_type = NULL;
	sqlite3 *conn = NULL;
	char *errtext = NULL;
	char *query = NULL;
	int res;
	passwd_scheme passwd_type;

	std_flags = get_module_options(argc, argv, &options);
	if(options_valid(options) != 0) {
		rc = PAM_AUTH_ERR;
		goto done;
	}

	if((rc = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS) {
		SYSLOGERR("could not retrieve user");
		goto done;
	}

	if(flags & PAM_PRELIM_CHECK) {
		/* at this point, this is the first time we get called */
		if((rc = pam_get_pass(pamh, &pass, PASSWORD_PROMPT, std_flags)) == PAM_SUCCESS) {
			if((rc = auth_verify_passwd(user, pass, options)) == PAM_SUCCESS) {
				rc = pam_set_item(pamh, PAM_OLDAUTHTOK, (const void *)pass);
				if(rc != PAM_SUCCESS) {
					SYSLOGERR("failed to set PAM_OLDAUTHTOK!");
				}
				goto done;
			} else {
				SYSLOG("password verification failed for '%s'", user);
				goto done;
			}
		} else {
			SYSLOGERR("could not retrieve password from '%s'", user);
			goto done;
		}
	} else if(flags & PAM_UPDATE_AUTHTOK) {
		rc = pam_get_item(pamh, PAM_OLDAUTHTOK, (const void **) &pass);
		if(rc != PAM_SUCCESS) {
			SYSLOGERR("could not retrieve old token");
			goto done;
		}
		rc = auth_verify_passwd(user, pass, options);
		if(rc != PAM_SUCCESS) {
			SYSLOG("(%s) user '%s' not authenticated.", pam_get_service(pamh, &service), user);
			goto done;
		}

		/* get and confirm the new passwords */
		rc = pam_get_confirm_pass(pamh, &newpass, PASSWORD_PROMPT_NEW, PASSWORD_PROMPT_CONFIRM, std_flags);
		if(rc != PAM_SUCCESS) {
			SYSLOGERR("could not retrieve new authentication tokens");
			goto done;
		}

		/* save the new password for subsequently stacked modules */
		rc = pam_set_item(pamh, PAM_AUTHTOK, (const void *)newpass);
		if(rc != PAM_SUCCESS) {
			SYSLOGERR("failed to set PAM_AUTHTOK!");
			goto done;
		}

		/* get password type from user */
		rc = pam_conversation(pamh, PASSWORD_PROMPT_TYPE, std_flags, &pass_type);
		if(rc != PAM_SUCCESS) {
			SYSLOGERR("failed to get pass type!");
			goto done;
		}

		passwd_type = atoi(pass_type);
		if(passwd_type == 0) {
			SYSLOGERR("invalid passwd type str!");
			rc = PAM_SYMBOL_ERR;
			goto done;
		}

		/* update the database */
		if(!(newpass_crypt = encrypt_passwd(passwd_type, newpass))) {
			SYSLOGERR("passwd encrypt failed");
			rc = PAM_BUF_ERR;
			goto done;
		}
		if(!(conn = pam_sqlite3_connect(options))) {
			SYSLOGERR("could not connect to database");
			rc = PAM_AUTHINFO_UNAVAIL;
			goto done;
		}

		DBGLOG("creating query");

		if(!(query = format_query(options->sql_set_passwd ? options->sql_set_passwd :
				"UPDATE %Ot SET %Op='%P' WHERE %Ou='%U'",
				options, user, newpass_crypt))) {
			SYSLOGERR("failed to construct sql query");
			rc = PAM_AUTH_ERR;
			goto done;
		}

		DBGLOG("query: %s", query);

		res = sqlite3_exec(conn, query, NULL, NULL, &errtext);
		free(query);

		if (SQLITE_OK != res) {
			SYSLOGERR("query failed[%d]: %s", res, errtext);
            sqlite3_free(errtext);  // error strings rom sqlite3_exec must be freed
			rc = PAM_AUTH_ERR;
			goto done;
		}

		/* if we get here, we must have succeeded */
	}

	SYSLOG("(%s) password for '%s' was changed.", pam_get_service(pamh, &service), user);
	rc = PAM_SUCCESS;

done:
	/* Do all cleanup in one place. */
	sqlite3_close(conn);
	if (newpass_crypt != NULL)
		memzero_explicit(newpass_crypt, strlen(newpass_crypt));
	free(newpass_crypt);
	free_module_options(options);
	return rc;
}

/* public: just succeed. */
PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;
}
