#include "common.h"
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include "log/ftplog.h"

#define R_O_ALL 0444

bool is_ip_addr(char* buf) {
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

void take_user_name(char username[])
{
    char cmd[] = "whoami";
    execute(cmd, username);
}

void fatal(const char* format, ...)
{
	va_list ap;
	char buf[1024];

	va_start(ap, format);
	vsnprintf(buf, sizeof(buf), format, ap);
	va_end(ap);
	fprintf(stderr, "%s\n", buf);
	exit(255);
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

bool has_pattern(char path[], char* pattern, FILE* pipe)
{
    char cmd[1024] = "grep ";
    char buffer[1];

    strcat(cmd, pattern);
    strcat(cmd, path);

    pipe = popen(cmd, "r");

    if(!pipe) fatal("Could not create pipe");
    

    size_t bytes_read = fread(buffer, 1, 1, pipe);

    if(bytes_read) return true;

    return false;
}

int bind_endpoint(  unsigned int _socket_fd, struct sockaddr_in* _endpoint_addr, 
                    unsigned int _endpoint_addr_size)
{
    if (bind(_socket_fd, (struct sockaddr*)_endpoint_addr, sizeof(*_endpoint_addr)) < 0) 
    {
        int error = errno;  
        char *error_message = strerror(error);
        printf("Bind failed: %s\n", error_message);
        fatal("Bind error\n");
    }

    return 1;
}

int listen_endpoint(unsigned int _socket_fd, unsigned int num)
{
    if (listen(_socket_fd, num) < 0) 
        fatal("Listen error\n");

    return 1;
}

int available_socket_fd(Stack* available)
{
    int sock = pop(available);
    return sock;
}

void date_time(char* res)
{
    time_t rawtime;
    struct tm *timeinfo;

    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(res, 64, "%Y-%m-%d %H:%M:%S", timeinfo); 
}

void disable_echo()
{
    struct termios oldt;
    tcgetattr(STDIN_FILENO, &oldt); 
    oldt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt); 
}

void enable_echo()
{
    struct termios oldt;
    tcgetattr(STDIN_FILENO, &oldt);
    oldt.c_lflag |= ECHO;   
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
}

int is_peer_correct(unsigned int sockfd1, unsigned int sockfd2)
{
    struct sockaddr_in addr1, addr2;
    socklen_t addr_len = sizeof(addr1);

    if(getpeername(sockfd1, (struct sockaddr*)&addr1, &addr_len) < 0 || 
       getpeername(sockfd2, (struct sockaddr*)&addr2, &addr_len) < 0)
    {
        perror("Get peer name \n");
        return 0;
    }

    char ip_addr1[INET_ADDRSTRLEN];
    char ip_addr2[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &addr1.sin_addr, ip_addr1, sizeof(ip_addr1));
    inet_ntop(AF_INET, &addr2.sin_addr, ip_addr2, sizeof(ip_addr2));

    LOG(SERVER_LOG, "IP ADDRESS: %s\n", ip_addr1);
    
    return strcmp(ip_addr1, ip_addr2) ? 0 : 1;
}

int hostname(unsigned int sockfd, char** ret)
{
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    if(getpeername(sockfd, (struct sockaddr*)&addr, &addr_len) < 0)
    {
        perror("Get peer name \n");
        return 0;
    }

    *ret = (char*) malloc(INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &addr.sin_addr, *ret, INET_ADDRSTRLEN);

    return 1;
}

void x_chdir(char* path)
{
    if (chdir(path) != 0) 
        perror("chdir() error");
}

void x_getcwd(char* cwd)
{
    if (!getcwd(cwd, BUF_LEN)) 
        perror("getcwd() error");
}

void x_abs_path(char* src, char* ret)
{
    if (!realpath(src, ret)) 
        perror("Error resolving path");
}