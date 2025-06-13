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

int bind_endpoint(  unsigned int _socket_fd, 
                    struct sockaddr_in* _endpoint_addr, 
                    unsigned int _endpoint_addr_size)
{
    if (bind(_socket_fd, (struct sockaddr*)_endpoint_addr, 
            sizeof(*_endpoint_addr)) < 0) 
    {
        int error = errno;  
        char *error_message = strerror(error);
        printf("Bind failed: %s\n", error_message);
        fatal("Bind error\n");
    }

    return 1;
}

int listen_endpoint(unsigned int _socket_fd, 
                    unsigned int num)
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

int port_number(unsigned int sockfd)
{
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    unsigned int port = 0;

    if (getsockname(sockfd, (struct sockaddr *)&addr, &addr_len) == -1) 
    {
        perror("Error getting socket name");
        close(sockfd);
        exit(1);
    }

    port = ntohs(addr.sin_port);

    return port;
}