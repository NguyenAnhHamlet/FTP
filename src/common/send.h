#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

// send msg over to the server
int send_msg(unsigned int socket_fd, unsigned int _BUF_LEN, char* msg);

// send integer
int send_int(unsigned int socket_fd, int num);




