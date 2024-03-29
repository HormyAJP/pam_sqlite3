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

#ifndef PAM_MOD_MISC_H
#define PAM_MOD_MISC_H

#include <sys/cdefs.h>

/* Options */
#define PAM_OPT_DEBUG			0x01
#define PAM_OPT_NO_WARN			0x02
#define PAM_OPT_USE_FIRST_PASS		0x04
#define	PAM_OPT_TRY_FIRST_PASS		0x08
#define PAM_OPT_USE_MAPPED_PASS		0x10
#define PAM_OPT_ECHO_PASS		0x20

#endif
