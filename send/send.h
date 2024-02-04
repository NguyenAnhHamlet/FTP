#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

// choose port 50000 as default port 
// for sending and receiving file
#define PORT 50000

// buffer size to be 1024, since 
// the name of file is usually really
// short and messsage display on CLI 
// not to be too long
#define BUF_LEN 1024

// create a new raw socket
// and return it
int cre_socket();

// create a network socket with 
// specify IP address and PORT
// and return it
int end_point(struct sockaddr_in* _endpoint_addr, char* _ip_addr, unsigned int _PORT);

// connect the fd to endpoint socket
int connect_endpoint(unsigned int _socket_fd, struct sockaddr_in* _endpoint_addr,
                     unsigned int _endpoint_addr_size);

int send_file(unsigned int _socket_fd, unsigned int _BUF_LEN ,char* _filename);

int send_msg(unsigned int _socket_fd, unsigned int _BUF_LEN, char* msg);




