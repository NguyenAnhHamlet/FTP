#include <netdb.h>
#include "common.h"
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>

R_O_ALL = 0444;

bool isIpAddr(char* buf) {
    int num_dots = 0;
    int num_octets = 0;
    int octet_value = 0;

    for(int i = 0; buf[i] != '\0'; i++) 
    {
        if (!isdigit(buf[i]) && buf[i] != '.') 
        {
            return false;
        }
        if (buf[i] == '.') 
        {
            num_dots++;
            // Check if the dot is not at the start or end, and if the previous character is not a dot
            if (i == 0 || i == strlen(buf) - 1 || buf[i - 1] == '.') 
                return false;

            // Check if the octet is within the valid range (0-255)
            if (octet_value < 0 || octet_value > 255) 
                return false;

            octet_value = 0; // Reset the octet value for the next octet
            num_octets++;
        } 
        else octet_value = octet_value * 10 + (buf[i] - '0');

    }

    // Check if there are exactly three dots, making four octets in total
    if (num_dots != 3 || num_octets != 3) 
        return false;

    // Check the last octet after the loop ends
    if (octet_value < 0 || octet_value > 255) 
        return false;

    return true;
}

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

int set_end_point(  struct sockaddr_in* _endpoint_addr, char* _ip_addr, unsigned int _PORT, 
                    unsigned int IPTYPE, Conn_Type type)
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
        errorLog("Unknown type\n");
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

int set_socket( _socketFTP* socket, unsigned int _sockfd, struct sockaddr_in* _endpoint_addr,
                char* _ip_addr, unsigned int _PORT_, unsigned int _endpoint_addr_size,
                unsigned int IPTYPE, Conn_Type type)
{
    int res = 1;
    socket->sockfd = _sockfd;
    res *= set_end_point(socket->endpoint_addr, socket->ip_addr, socket->PORT_, IPTYPE, type);

    switch (type)
    {
    case CLIENT:
        res *= connect_endpoint(socket->sockfd, socket->endpoint_addr, socket->endpoint_addr_size);
        break;
    case SERVER:
    {
        res *= bind_endpoint(socket->sockfd, socket->endpoint_addr,socket->endpoint_addr_size);
        res *= listen_endpoint(socket->sockfd, NUMCLIENT); 
        break;
    }

    default:

        break;
    }
    res *= connect_endpoint(socket->sockfd, socket->endpoint_addr, socket->endpoint_addr_size);
    
    return res > 0;
}

_socketFTP* cre_FTPSocket(char* _ip_addr, unsigned int IPTYPE,  Conn_Type type)
{
    int sock_fd;
    struct sockaddr_in* endpoint_address = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
    int opt = 1;
    int addrlen = sizeof(struct sockaddr_in);

    _socketFTP* socket = (_socketFTP*)malloc(sizeof(_socketFTP));

    set_socket(socket, cre_socket(), endpoint_address, _ip_addr, PORT, addrlen, IPTYPE, type);
}

void destroy_FTPSocket(_socketFTP* socket)
{
    free(socket->endpoint_addr);
    free(socket);
}

void execute(char cmd[], char res[])
{
    FILE *fp = popen(cmd, "r");
    char line[1035];
    if (fp == NULL) 
    {
        perror("popen failed");
        exit(1);
    }

    while (fgets(line, sizeof(line), fp) != NULL) 
    {
        strcat(res, line);
    }

    /* close */
    pclose(fp);   
}

void takeUserName(char username[])
{
    char cmd[] = "whoami";
    execute(cmd, username);
}

void errorLog(char err[])
{
    printf("%s\n",err);
    exit(1);
}

unsigned int size_buffer(char buff[])
{
    unsigned int size = 0;

    while(buff[size] != '\0')
    {
        size++;
    }

    return size;
}

bool has_Pattern(char path[], char* pattern, FILE* pipe)
{
    char cmd[1024] = "grep ";
    char buffer[1];

    strcat(cmd, pattern);
    strcat(cmd, path);

    pipe = popen(cmd, "r");

    if(!pipe) errorLog("Could not create pipe");
    

    size_t bytes_read = fread(buffer, 1, 1, pipe);

    if(bytes_read) return true;

    return false;
}

int bind_endpoint(  unsigned int _socket_fd, struct sockaddr_in* _endpoint_addr, 
                    unsigned int _endpoint_addr_size)
{
    if (bind(_socket_fd, (struct sockaddr*)&_endpoint_addr, _endpoint_addr_size) < 0) 
        errorLog("Bind error\n");

    return 1;
}

int listen_endpoint(unsigned int _socket_fd, unsigned int num)
{
    if (listen(_socket_fd, num) < 0) 
        errorLog("Listen error\n");

    return 1;
}

int accept_New_ConnectionFTP(_socketFTP* socket )
{
    return accept(socket->sockfd, socket->endpoint_addr, socket->endpoint_addr_size);
}

int available_SocketFD(Stack* available)
{
    int sock = pop(available);
    return sock;
}

int get_host_name(char* host)
{
    if(strchr(host, '.') == 0)
    {
        struct addrinfo hints;
        struct addrinfo *ai = NULL;
        int errgai;
        memset(&hints, 0, sizeof(hints));

        hints.ai_family = AF_UNSPEC;
        hints.ai_flags = AI_CANONNAME;
        hints.ai_socktype = SOCK_STREAM;

        errgai = getaddrinfo(host, NULL, &hints, &ai);
        if (errgai == 0) {
            if (ai->ai_canonname != NULL)
                host = xstrdup(ai->ai_canonname);
            freeaddrinfo(ai);
        }
        return Success;
    }

    return Unknown;

}
