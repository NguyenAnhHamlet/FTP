#ifndef __SOCKET_FTP__
#define __SOCKET_FTP__

#include "common/socket_ftp.h"
#include "common/common.h"
typedef struct 
{
    unsigned int sockfd;
    struct sockaddr_in* endpoint_addr;
    char ip_addr[IP_LEN];
    unsigned int PORT_;
    unsigned int endpoint_addr_size;
    unsigned int op;
    int* opt;
} socket_ftp;

int set_socket( socket_ftp* socket, unsigned int _sockfd, 
                struct sockaddr_in* _endpoint_addr,
                char* _ip_addr, unsigned int _PORT_, 
                unsigned int _endpoint_addr_size,
                socklen_t IPTYPE,  endpoint_type type, 
                channel_type c_type);

socket_ftp* create_ftp_socket(char* _ip_addr, socklen_t IPTYPE, 
                              endpoint_type type, unsigned int PORT,
                              channel_type c_type, unsigned int sockfd);

void destroy_ftp_socket(socket_ftp* socket);

// copy all information from org to dest
void ftp_socket_cp(socket_ftp* org, socket_ftp* dest);

// only create a raw ftp_socket with no data
socket_ftp* socket_ftp_raw_cre();

// create a new raw socket
// and return it
int cre_socket();

// create a network socket with 
// specify IP address and PORT
// and return it
int set_end_point(struct sockaddr_in* _endpoint_addr, 
                  char* _ip_addr, unsigned int _PORT,
                  socklen_t IPTYPE, endpoint_type type);

// connect the fd to endpoint socket
int connect_endpoint(unsigned int _socket_fd, 
                     struct sockaddr_in* _endpoint_addr,
                     unsigned int _endpoint_addr_size);

int accept_new_connection_ftp(socket_ftp* socket);
unsigned int socket_ftp_get_port(socket_ftp* socket);

#endif