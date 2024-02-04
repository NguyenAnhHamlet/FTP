#include "send.h"

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

int end_point(struct sockaddr_in* _endpoint_addr, char* _ip_addr, unsigned int _PORT)
{
    _endpoint_addr->sin_family = AF_INET;
    _endpoint_addr->sin_port = htons(_PORT);

    if (inet_pton(AF_INET, _ip_addr , &(_endpoint_addr->sin_addr)) <= 0) 
    {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
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

int send_file(unsigned int _socket_fd, unsigned int _BUF_LEN ,char* _filename)
{
    FILE* file = fopen(_filename, "rb");
    int byte;

    if (file == NULL) 
    {
        perror("Error opening file");
        close(_socket_fd);
        exit(EXIT_FAILURE);
    }

    while ((byte = fgetc(file)) != EOF) 
    {
        send(_socket_fd, &byte, sizeof(byte), 0);
    }

}

int send_msg(unsigned int _socket_fd, unsigned int _BUF_LEN, char* msg)
{
    if(send(_socket_fd, msg, _BUF_LEN, 0) < 0)
    {
        printf("Sending message error\n");
        return -1;
    }

    return 1;
}