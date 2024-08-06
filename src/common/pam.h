#ifndef __PAM__
#define __PAM__


#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>

int auth_pam_password(struct passwd *pw, const char *password);
void finish_pam(void);
void pam_cleanup_proc(void *context);
void start_pam(struct passwd *pw);
void do_pam_setcred();
int do_pam_account(char *username, char *remote_user);

#endif 
