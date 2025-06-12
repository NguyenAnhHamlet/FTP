#ifndef __PAM__
#define __PAM__


#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>

int auth_pam_password(struct passwd *pw, char *password);
void finish_pam(void);
void pam_cleanup_proc(void *context);
void start_pam(struct passwd *pw);
int do_pam_account(char *username);

#endif 
