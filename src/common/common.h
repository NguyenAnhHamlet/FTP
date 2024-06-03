#ifndef __COMMON__
#define __COMMON__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include "stack.h"

// choose port 50000 as default port 
// for sending and receiving data
#define PORT 50000

// choose port 51000 for initial setup 
// and initial authentication
#define PORT_SETUP 51000

// buffer size to be 1024, since 
// the name of file is usually really
// short and messsage display on CLI 
// not to be too long
#define BUF_LEN 1024

#define NUMCLIENT 2056


mode_t R_O_ALL;

typedef enum Status
{
    Faillure,
    Success,
    Unknown 
} Status;

typedef enum Conn_Type
{
    CLIENT,
    SERVER
} Conn_Type;

typedef enum option
{
    INTERACTIVE_MODE = 1,
    PASSIVE_MODE = 2,
    AUTO_LOGGIN = 4,
    NAME_GLOBBING = 8,
    VERBOSE_OUTPUT = 16,
    DEBUG_ENB_OP = 32
} option;

typedef struct _socketFTP
{
    unsigned int sockfd;
    struct sockaddr_in* endpoint_addr;
    char* ip_addr;
    unsigned int PORT_;
    unsigned int endpoint_addr_size;
    unsigned int op;
} _socketFTP;

int set_socket( _socketFTP* socket, unsigned int _sockfd, struct sockaddr_in* _endpoint_addr,
                char* _ip_addr, unsigned int _PORT_, unsigned int _endpoint_addr_size,
                unsigned int IPTYPE,  Conn_Type type);

_socketFTP* cre_FTPSocket(char* _ip_addr, unsigned int IPTYPE, Conn_Type type);
void destroy_FTPSocket(_socketFTP* socket);
// create a new raw socket
// and return it
int cre_socket();

// create a network socket with 
// specify IP address and PORT
// and return it
int set_end_point(struct sockaddr_in* _endpoint_addr, char* _ip_addr, unsigned int _PORT,
                  unsigned int IPTYPE, Conn_Type type);

// connect the fd to endpoint socket
int connect_endpoint(unsigned int _socket_fd, struct sockaddr_in* _endpoint_addr,
                     unsigned int _endpoint_addr_size);

bool isIpAddr(char* buf);

void execute(char cmd[], char res[]);

void takeUserName(char username[]);

void errorLog(char err[]);

unsigned int size_buffer(char buff[]);

bool has_Pattern(char path[], char* pattern, FILE* pipe);

int bind_endpoint(  unsigned int _socket_fd, struct sockaddr_in* _endpoint_addr, 
                    unsigned int _endpoint_addr_size);

int listen_endpoint(unsigned int _socket_fd, unsigned int num);

int accept_New_ConnectionFTP(_socketFTP* socket);

int available_SocketFD(Stack* available);

int get_host_name(char* host);

#endif