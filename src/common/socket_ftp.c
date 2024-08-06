#include "socket_ftp.h"
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include "common.h"

int cre_socket()
{
    int client_fd;
    if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
    {
        printf("\n Socket creation error \n");
        return -1;
    }


    printf("Created socket fd\n");

    return client_fd;
}

int set_end_point(struct sockaddr_in* _endpoint_addr, char* _ip_addr,
                  unsigned int _PORT, unsigned int IPTYPE, 
                  endpoint_type type)
{
    if(IPTYPE != AF_INET && IPTYPE != AF_INET6) return -1;

    _endpoint_addr->sin_family = IPTYPE;
    _endpoint_addr->sin_port = htons(_PORT);

    switch (type)
    {
    case CLIENT:
    {
        if (inet_pton(AF_INET, _ip_addr , &(_endpoint_addr->sin_addr)) <= 0) 
        {
            printf("\nInvalid address/ Address not supported \n");
            return -1;
        }
        break;
    }

    case SERVER:
    {
        _endpoint_addr->sin_addr.s_addr = INADDR_ANY;
        break;
    }
    
    default:
        fatal("Unknown type\n");
        break;
    }

    return 1;
}

int connect_endpoint(unsigned int _socket_fd, struct sockaddr_in* _endpoint_addr,
                     unsigned int _endpoint_addr_size)
{
    if ((connect(_socket_fd, (struct sockaddr*)_endpoint_addr, sizeof(_endpoint_addr))) < 0) 
    {
        printf("\nConnection Failed \n");
        return -1;
    }

    return 1;
}

int set_socket( socket_ftp* socket, unsigned int _sockfd, struct sockaddr_in* _endpoint_addr,
                char* _ip_addr, unsigned int _PORT_, unsigned int _endpoint_addr_size,
                unsigned int IPTYPE, endpoint_type type, channel_type c_type)
{
    int res = 1;
    socket->sockfd = _sockfd;
    socket->endpoint_addr = _endpoint_addr;
    strcpy(socket->ip_addr, _ip_addr);
    socket->PORT_ = _PORT_;
    socket->endpoint_addr_size = _endpoint_addr_size;
    int opt = 1;

    switch (type)
    {
    case CLIENT:
    {
        res &= connect_endpoint(socket->sockfd, socket->endpoint_addr, 
                                socket->endpoint_addr_size);
        break;
    }
    case SERVER:
    {
        res &= set_end_point(socket->endpoint_addr, socket->ip_addr, 
                                socket->PORT_, IPTYPE, type);

        if (setsockopt(socket->sockfd, SOL_SOCKET,
                SO_REUSEADDR | SO_REUSEPORT, &opt,
                sizeof(opt))) 
        {
            LOG("Set socket option failed\n");
            return 0;
        }

        res &= bind_endpoint(socket->sockfd, socket->endpoint_addr,
                             socket->endpoint_addr_size);        

        switch (c_type)
        {
        case DATA:
        {
            res &= listen_endpoint(socket->sockfd, 1);
            break;
        }
        case SERVER_LISTENTING:
        {
            res &= listen_endpoint(socket->sockfd, NUMCLIENT); 
            break;
        }
        
        default:
            break;
        }
    }

    default:
        LOG("Unknown endpoint_type\n");
        break;
    }
    
    return res > 0;
}

socket_ftp* create_ftp_socket(char* _ip_addr, unsigned int IPTYPE,  
                              endpoint_type type, unsigned int PORT, 
                              channel_type c_type, unsigned int sockfd )
{
    int sock_fd;
    struct sockaddr_in* endpoint_address = 
            (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));

    int opt = 1;
    int addrlen = sizeof(struct sockaddr_in);

    socket_ftp* socket = (socket_ftp*)malloc(sizeof(socket_ftp));

    set_socket(socket, sockfd, endpoint_address, _ip_addr, 
               PORT, addrlen, IPTYPE, type, c_type);
}

void destroy_ftp_socket(socket_ftp* socket)
{
    free(socket->endpoint_addr);
    free(socket);
}

int accept_new_connection_ftp(socket_ftp* socket )
{
    return accept(socket->sockfd, socket->endpoint_addr, socket->endpoint_addr_size);
}