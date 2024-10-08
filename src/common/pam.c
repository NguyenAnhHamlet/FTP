#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include "log/ftplog.h"
#include "common.h"
#include <security/pam_appl.h>
#include "common/pam.h"

static int pamconv(int num_msg, const struct pam_message **msg,
	  struct pam_response **resp, void *appdata_ptr);

static struct pam_conv conv = {
	pamconv,
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

int auth_pam_password(struct passwd *pw, char *password)
{
    int pam_retval;

	/* deny if no user. */
	if (pw == NULL)
		return 0;
	
    pampasswd = password;

	LOG(SERVER_LOG, "RUNNNING HERE 3 %s\n", pampasswd);
    pam_retval = ((pam_handle_t *)pamh, 0);

    if (pam_retval == PAM_SUCCESS) 
    {
        LOG(SERVER_LOG, "PAM Password authentication accepted for user \"%.100s\"", pw->pw_name);
        return 1;
	} 
    else
    {
		LOG(SERVER_LOG, "PAM Password authentication for \"%.100s\" failed: %s", 
			pw->pw_name, pam_strerror((pam_handle_t *)pamh, pam_retval));
		return 0;
	}
}				

void start_pam(struct passwd *pw)
{
	int pam_retval;

	LOG(SERVER_LOG, "Starting up PAM with username \"%.200s\"", pw->pw_name);

	pam_retval = pam_start("sftp", pw->pw_name, &conv, (pam_handle_t**)&pamh);
	if (pam_retval != PAM_SUCCESS)
		LOG(SERVER_LOG, "PAM initialisation failed: %.200s", pam_strerror((pam_handle_t *)pamh, pam_retval));

	pam_cleanup_proc(NULL);
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




