#include "common.h"
#include <stdlib.h>

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

int set_end_point(struct sockaddr_in* _endpoint_addr, char* _ip_addr, unsigned int _PORT, unsigned int IPTYPE)
{
    if(IPTYPE != AF_INET && IPTYPE != AF_INET6) return -1;

    _endpoint_addr->sin_family = IPTYPE;
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

int set_socket( _socketFTP* socket, unsigned int _sockfd, struct sockaddr_in* _endpoint_addr,
                char* _ip_addr, unsigned int _PORT_, unsigned int _endpoint_addr_size,
                unsigned int IPTYPE)
{
    int res = 1;
    socket->sockfd = cre_socket();
    res *= set_end_point(socket->endpoint_addr, socket->ip_addr, socket->PORT_, IPTYPE);
    res *= connect_endpoint(socket->sockfd, socket->endpoint_addr, socket->endpoint_addr_size);
    
    return res;
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
