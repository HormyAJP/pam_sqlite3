/*
 * Copyright (c) 2000. Leon Breedt, Copyright (c) 2002 David D.W. Downey
 */

/* $Id: pam_get_service.c,v 1.1 2003/06/20 09:56:31 ek Exp $ */
#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <string.h>

static const char* UNKNOWN_SERVICE = "<Unknown Service>";

const char* pam_get_service(pam_handle_t *pamh, const char **service)
{
	if (pam_get_item(pamh, PAM_SERVICE, (const void**)service) != PAM_SUCCESS)
        *service = UNKNOWN_SERVICE;
    return *service;
}
