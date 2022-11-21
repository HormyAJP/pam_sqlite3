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

#ifndef PAM_SQLITE3_CONVERSATION_H
#define PAM_SQLITE3_CONVERSATION_H

#include <security/pam_modules.h>

int pam_conversation(pam_handle_t *pamh, const char *prompt, int options, char **res);
int pam_get_pass(pam_handle_t *pamh, const char **passp,
		 const char *prompt, int options);
int pam_get_confirm_pass(pam_handle_t *pamh, const char **passp,
			 const char *prompt1, const char *prompt2, int options);

#endif //PAM_SQLITE3_CONVERSATION_H
