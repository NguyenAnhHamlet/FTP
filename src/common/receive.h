#ifndef __RECEIVE__
#define __RECEIVE__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "common/status.h"

// recv msg over to the server
int recv_msg(unsigned int _socket_fd, unsigned int _BUF_LEN, char* msg);

// recv integer
int recv_int(unsigned int _socket_fd, int* num);

#endif