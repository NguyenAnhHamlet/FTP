#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include "ftplog.h"
#include "common.h"

static int pamconv(int num_msg, const struct pam_message **msg,
	  struct pam_response **resp, void *appdata_ptr);

static struct pam_conv conv = {
	pamconv,
	NULL
};

static struct pam_handle_t *pamh = NULL;
static const char *pampasswd = NULL;
static char *pamconv_msg = NULL;

// receive the message from PAM
// get the response result of PAM authentication
static int pamconv(int num_msg, const struct pam_message **msg,
	struct pam_response **resp, void *appdata_ptr)
{
	struct pam_response *reply;
	int count;
	size_t msg_len;
	char *p;

	/* PAM will free this later */
	reply = malloc(num_msg * sizeof(*reply));
	if (reply == NULL)
		return PAM_CONV_ERR; 

	for(count = 0; count < num_msg; count++) {
		switch (msg[count]->msg_style) {
			case PAM_PROMPT_ECHO_OFF:
				if (pampasswd == NULL) {
					free(reply);
					return PAM_CONV_ERR;
				}
				reply[count].resp_retcode = PAM_SUCCESS;
				reply[count].resp = pampasswd;
				break;

			case PAM_TEXT_INFO:
				reply[count].resp_retcode = PAM_SUCCESS;
				reply[count].resp = "";

                // TODO
                // Allocate memory for pamconv_msg 
                // Add message into pamconv_msg 
                // seperate by \n\0

				break;

			case PAM_PROMPT_ECHO_ON:
			case PAM_ERROR_MSG:
			default:
				free(reply);
				return PAM_CONV_ERR;
		}
	}

	*resp = reply;

	return PAM_SUCCESS;
}

int auth_pam_password(struct passwd *pw, const char *password)
{
    int pam_retval;

	/* deny if no user. */
	if (pw == NULL)
		return 0;
	
    pampasswd = password;

    pam_retval = pam_authenticate((pam_handle_t *)pamh, 0);

    if (pam_retval == PAM_SUCCESS) 
    {
        LOG("PAM Password authentication accepted for user \"%.100s\"", pw->pw_name);
        return Success;
	} 
    else
    {
		LOG("PAM Password authentication for \"%.100s\" failed: %s", 
			pw->pw_name, PAM_STRERROR((pam_handle_t *)pamh, pam_retval));
		return Faillure;
	}
}

int do_pam_account(char *username, char *remote_user)
{
	int pam_retval;

	debug("PAM setting rhost to \"%.200s\"", get_canonical_hostname());
	pam_retval = pam_set_item((pam_handle_t *)pamh, PAM_RHOST, 
		get_canonical_hostname());
	if (pam_retval != PAM_SUCCESS) 
	{
		fatal("PAM set rhost failed: %.200s", PAM_STRERROR((pam_handle_t *)pamh, pam_retval));
	}

	if (remote_user != NULL) 
	{
		debug("PAM setting ruser to \"%.200s\"", remote_user);
		pam_retval = pam_set_item((pam_handle_t *)pamh, PAM_RUSER, remote_user);
		if (pam_retval != PAM_SUCCESS) 
		{
			fatal("PAM set ruser failed: %.200s", PAM_STRERROR((pam_handle_t *)pamh, pam_retval));
		}
	}

	pam_retval = pam_acct_mgmt((pam_handle_t *)pamh, 0);
	if (pam_retval != PAM_SUCCESS) 
	{
		LOG("PAM rejected by account configuration: %.200s", PAM_STRERROR((pam_handle_t *)pamh, pam_retval));
		return(0);
	}
	
	return Success;
}

void do_pam_setcred()
{
	int pam_retval;
 
	debug("PAM establishing creds");
	pam_retval = pam_setcred((pam_handle_t *)pamh, PAM_ESTABLISH_CRED);
	if (pam_retval != PAM_SUCCESS)
		fatal("PAM setcred failed: %.200s", PAM_STRERROR((pam_handle_t *)pamh, pam_retval));
}

void start_pam(struct passwd *pw)
{
	int pam_retval;

	debug("Starting up PAM with username \"%.200s\"", pw->pw_name);

	pam_retval = pam_start("ftp", pw->pw_name, &conv, (pam_handle_t**)&pamh);
	if (pam_retval != PAM_SUCCESS)
		fatal("PAM initialisation failed: %.200s", PAM_STRERROR((pam_handle_t *)pamh, pam_retval));

	pam_cleanup_proc(NULL);
}

void pam_cleanup_proc(void *context)
{
	int pam_retval;

	if (pamh != NULL)
	{
		pam_retval = pam_close_session((pam_handle_t *)pamh, 0);
		if (pam_retval != PAM_SUCCESS) {
			LOG("Cannot close PAM session: %.200s", 
			PAM_STRERROR((pam_handle_t *)pamh, pam_retval));
		}

		pam_retval = pam_setcred((pam_handle_t *)pamh, PAM_DELETE_CRED);
		if (pam_retval != PAM_SUCCESS) {
			LOG("Cannot delete credentials: %.200s", 
			PAM_STRERROR((pam_handle_t *)pamh, pam_retval));
		}

		pam_retval = pam_end((pam_handle_t *)pamh, pam_retval);
		if (pam_retval != PAM_SUCCESS) {
			LOG("Cannot release PAM authentication: %.200s", 
			PAM_STRERROR((pam_handle_t *)pamh, pam_retval));
		}
	}
}

void finish_pam(void)
{
	pam_cleanup_proc(NULL);
	fatal_remove_cleanup(&pam_cleanup_proc, NULL);
}




