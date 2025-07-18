#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include "log/ftplog.h"
#include "common.h"
#include <security/pam_appl.h>
#include "common/pam.h"
#include "algo/algo.h"

static int pamconv(int num_msg, const struct pam_message **msg,
	  struct pam_response **resp, void *appdata_ptr);

static struct pam_conv conv = {
	&pamconv,
	NULL
};

static struct pam_handle_t *pamh = NULL;
static char *pampasswd = NULL;
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
	reply = (struct pam_response*) 
			 malloc(num_msg * sizeof(struct pam_response));	
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
				reply[count].resp = strdup(pampasswd);
				break;
			case PAM_TEXT_INFO:
			case PAM_PROMPT_ECHO_ON:
			case PAM_ERROR_MSG:	
				reply[count].resp_retcode = PAM_SUCCESS;
        		reply[count].resp = 0;	
			default:
				free(reply);
				return PAM_CONV_ERR;
		}
	}

	*resp = reply;

	return PAM_SUCCESS;
}

int auth_pam_password(struct passwd *pw, char *password)
{
    int pam_retval;

	/* deny if no user. */
	if (pw == NULL)
		return 0;
	
    pampasswd = strdup(password);

    pam_retval = pam_authenticate((pam_handle_t *)pamh, 0);

    if (pam_retval == PAM_SUCCESS) 
    {
        LOG(SERVER_LOG, 
			"PAM Password authentication accepted for user \"%.100s\"", 
			pw->pw_name);
        return 1;
	} 
    else
    {
		LOG(SERVER_LOG, 
			"PAM Password authentication for \"%.100s\" failed: %s", 
			pw->pw_name, pam_strerror((pam_handle_t *)pamh, 
			pam_retval));
		return 0;
	}
}	

int do_pam_account(char *username)
{
	int pam_retval;
	pam_retval = pam_acct_mgmt((pam_handle_t *)pamh, 0);

	switch (pam_retval) {
		case PAM_SUCCESS:
			/* This is what we want */
			break;
		case PAM_NEW_AUTHTOK_REQD:
			/* flag that password change is necessary */
			LOG(SERVER, "PAM rejected, requiring password change[%d]: "
			    "%.200s", pam_retval, pam_strerror(pamh, 
			    pam_retval));
			return 0;
		default:
			LOG(SERVER, "PAM rejected by account configuration[%d]: "
			    "%.200s", pam_retval, pam_strerror(pamh, 
			    pam_retval));
			return 0;
	}

	return 1;
}

void start_pam(struct passwd *pw)
{
	int pam_retval;

	LOG(SERVER_LOG, 
		"Starting up PAM with username \"%.200s\"\n", 
		pw->pw_name);

	pam_retval = pam_start("sftp", pw->pw_name, &conv, &pamh);

	if (pam_retval != PAM_SUCCESS)
	{
		pam_cleanup_proc(NULL);
		fatal("PAM initialisation failed: %.200s", 
			  pam_strerror((pam_handle_t *)pamh, pam_retval));
	}

}

void pam_cleanup_proc(void *context)
{
	int pam_retval;

	if (pamh != NULL)
	{
		pam_retval = pam_close_session((pam_handle_t *)pamh, 0);
		if (pam_retval != PAM_SUCCESS) {
			LOG(SERVER_LOG, "Cannot close PAM session: %.200s", 
			pam_strerror((pam_handle_t *)pamh, pam_retval));
		}

		pam_retval = pam_setcred((pam_handle_t *)pamh, PAM_DELETE_CRED);
		if (pam_retval != PAM_SUCCESS) {
			LOG(SERVER_LOG, "Cannot delete credentials: %.200s", 
			pam_strerror((pam_handle_t *)pamh, pam_retval));
		}

		pam_retval = pam_end((pam_handle_t *)pamh, pam_retval);
		if (pam_retval != PAM_SUCCESS) {
			LOG(SERVER_LOG, "Cannot release PAM authentication: %.200s", 
			pam_strerror((pam_handle_t *)pamh, pam_retval));
		}
	}
}

void finish_pam(void)
{
	pam_cleanup_proc(NULL);
}




