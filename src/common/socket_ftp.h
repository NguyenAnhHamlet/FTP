#ifndef __SOCKET_FTP__
#define __SOCKET_FTP__

typedef struct 
{
    unsigned int sockfd;
    struct sockaddr_in* endpoint_addr;
    char* ip_addr;
    unsigned int PORT_;
    unsigned int endpoint_addr_size;
    unsigned int op;
} socket_ftp;

int set_socket( socket_ftp* socket, unsigned int _sockfd, struct sockaddr_in* _endpoint_addr,
                char* _ip_addr, unsigned int _PORT_, unsigned int _endpoint_addr_size,
                unsigned int IPTYPE,  endpoint_type type, channel_type c_type);

socket_ftp* create_ftp_socket(char* _ip_addr, unsigned int IPTYPE, 
                              endpoint_type type, unsigned int PORT,
                              channel_type c_type);

void destroy_ftp_socket(socket_ftp* socket);

// create a new raw socket
// and return it
int cre_socket();

// create a network socket with 
// specify IP address and PORT
// and return it
int set_end_point(struct sockaddr_in* _endpoint_addr, char* _ip_addr, unsigned int _PORT,
                  unsigned int IPTYPE, endpoint_type type);

// connect the fd to endpoint socket
int connect_endpoint(unsigned int _socket_fd, struct sockaddr_in* _endpoint_addr,
                     unsigned int _endpoint_addr_size);

int accept_new_connection_ftp(socket_ftp* socket);

#endif