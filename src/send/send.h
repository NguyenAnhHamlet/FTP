#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

// send file over to the server
int send_file(unsigned int _socket_fd, unsigned int _BUF_LEN ,char* _filename, status_ftp* status);

// send msg over to the server
int send_msg(unsigned int _socket_fd, unsigned int _BUF_LEN, char* msg);

// send integer
int send_int(unsigned int _socket_fd, int num);




