#ifndef __SERVER__
#define __SERVER__

#include "common.h"
#include "receive.h"
#include "send.h"

void* pubkeyAuthenThreadFunc(void* vargp);

int handleRequestServer(int sockfd, char req[]);

int sendRespondServer(int sockfd, char res[]);


#endif