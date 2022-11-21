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
#include <security/pam_appl.h>

#include "pam_mod_misc.h"
#include "pam_sqlite3.h"
#include "pam_sqlite3_conversation.h"

int
pam_conversation(pam_handle_t *pamh, const char *prompt, int options, char **res)
{
	int retval;
	const void *item;
	const struct pam_conv *conv;
	struct pam_message msg;
	const struct pam_message *msgs[1];
	struct pam_response *resp;

	if ((retval = pam_get_item(pamh, PAM_CONV, &item)) != PAM_SUCCESS)
		return retval;
	conv = (const struct pam_conv *)item;
	msg.msg_style = options & PAM_OPT_ECHO_PASS ?
		PAM_PROMPT_ECHO_ON : PAM_PROMPT_ECHO_OFF;
	msg.msg = (char *)prompt;
	msgs[0] = &msg;
	if ((retval = conv->conv(1, msgs, &resp, conv->appdata_ptr)) !=
		PAM_SUCCESS)
		return retval;
	*res = strdup(resp[0].resp);
	memzero_explicit(resp[0].resp, strlen(resp[0].resp));
	free(resp[0].resp);
	free(resp);
	return PAM_SUCCESS;
}

int
pam_get_pass(pam_handle_t *pamh, const char **passp, const char *prompt, int options)
{
	int retval;
	const void *item = NULL;
	char *conv_res = NULL;

	/*
	 * Grab the already-entered password if we might want to use it.
	 */
	if (options & (PAM_OPT_TRY_FIRST_PASS | PAM_OPT_USE_FIRST_PASS)) {
		if ((retval = pam_get_item(pamh, PAM_AUTHTOK, &item)) !=
			PAM_SUCCESS)
			return retval;
	}

	if (item == NULL) {
		/* The user hasn't entered a password yet. */
		if (options & PAM_OPT_USE_FIRST_PASS)
			return PAM_AUTH_ERR;
		/* Use the conversation function to get a password. */
		if ((retval = pam_conversation(pamh, prompt, options, &conv_res)) !=
			PAM_SUCCESS)
		return retval;
	if ((retval = pam_set_item(pamh, PAM_AUTHTOK, conv_res)) != PAM_SUCCESS) {
		free(conv_res);
		return retval;
	}
	free(conv_res);

	if ((retval = pam_get_item(pamh, PAM_AUTHTOK, &item)) != PAM_SUCCESS)
			return retval;
	}
	*passp = (const char *)item;
	return PAM_SUCCESS;
}

int
pam_get_confirm_pass(pam_handle_t *pamh, const char **passp, const char *prompt1,
		     const char *prompt2, int options)
{
	int retval, i;
	const void *item = NULL;
	const struct pam_conv *conv;
	struct pam_message msgs[2];
	const struct pam_message *pmsgs[2];
	struct pam_response *resp;

	if ((retval = pam_get_item(pamh, PAM_CONV, &item)) != PAM_SUCCESS)
		return retval;

	conv = (const struct pam_conv *)item;
	for(i = 0; i < 2; i++)
		msgs[i].msg_style = options & PAM_OPT_ECHO_PASS ? 
			PAM_PROMPT_ECHO_ON : PAM_PROMPT_ECHO_OFF;
	msgs[0].msg = (char *)prompt1;
	msgs[1].msg = (char *)prompt2;
	pmsgs[0] = &msgs[0];
	pmsgs[1] = &msgs[1];
	
	if((retval = conv->conv(2, pmsgs, &resp, conv->appdata_ptr)) != PAM_SUCCESS)
		return retval;

	if(!resp)
		return PAM_AUTHTOK_RECOVERY_ERR;
	if(strcmp(resp[0].resp, resp[1].resp) != 0)
		return PAM_AUTHTOK_RECOVERY_ERR;

	retval = pam_set_item(pamh, PAM_AUTHTOK, resp[0].resp);
	memzero_explicit(resp[0].resp, strlen(resp[0].resp));
	memzero_explicit(resp[1].resp, strlen(resp[1].resp));
	free(resp[0].resp);
	free(resp[1].resp);
	free(resp);

	if(retval == PAM_SUCCESS) {
		item = NULL;
		retval = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&item);
		*passp = item;
	}

	return retval;
}
