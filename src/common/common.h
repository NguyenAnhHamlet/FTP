#ifndef __COMMON__
#define __COMMON__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include "algo/stack.h"

// choose port 50000 as default port 
// for sending and receiving data
#define PORT_DATA 50000

// choose port 51000 for initial setup 
// and initial authentication
#define PORT_CONTROL 51000

#define BUF_LEN 4096    

#define NUMCLIENT 2056


mode_t R_O_ALL;

typedef enum 
{
    Faillure,
    Success,
    Unknown 
} Status;

typedef enum 
{
    CLIENT,
    SERVER
} endpoint_type;

typedef enum 
{
    CONTROL,
    DATA,
    SERVER_LISTENING
} channel_type;


bool is_ip_addr(char* buf);

void execute(char cmd[], char res[]);

void take_user_name(char username[]);

void fatal(const char* format, ...);

unsigned int size_buffer(char buff[]);

bool has_pattern(char path[], char* pattern, FILE* pipe);

int bind_endpoint(  unsigned int _socket_fd, struct sockaddr_in* _endpoint_addr, 
                    unsigned int _endpoint_addr_size);

int listen_endpoint(unsigned int _socket_fd, unsigned int num);

int available_socket_fd(Stack* available);

int get_host_name(char* host);

#endif