#include "ftp.h"
#include "send.h"
#include "establish.h"
#include "common.h"
#include <stdbool.h>
#include <stdlib.h>
#include "send.h"
#include "secure.h"
#include "timer.h"
#include <time.h>

void ipv4_op(_socketFTP* socketFTP)
{
    socketFTP->endpoint_addr->sin_family = AF_INET;
}

void ipv6_op(_socketFTP* socketFTP)
{
    socketFTP->endpoint_addr->sin_family = AF_INET6;
}

void passmode(_socketFTP* socketFTP)
{
    socketFTP->passive_mode = 1;
}

void int_off(_socketFTP* socketFTP)
{
    socketFTP->interactive_mode = 0;
}

void aulog_dis(_socketFTP* socketFTP)
{
    socketFTP->auto_loggin = 0;
}

void glob_dis(_socketFTP* socketFTP)
{
    socketFTP->name_globbing = 0;
}

void verbose_enb(_socketFTP* socketFTP)
{
    socketFTP->verbose_output = 1;
}

void debug_enb(_socketFTP* socketFTP)
{
    socketFTP->debug = 1;
}

int sendClientRequest(char req[], Asym_Infos* as_infos, Timer* timer)
{
    if(!timer) return Faillure;

    setTimer(timer, time(NULL), 10);

    startTimer(timer, callBackTimer);

    if(!send_msg(as_infos->setupSocket, BUF_LEN, req)) return Faillure;

    cancelTimer(timer);

    return Success;
}

int handleRequest(char req[], Asym_Infos* as_infos, Timer* timer)
{
    int res = Faillure;

    if (strcmp(req, QUIT) == 0) return quit();
    else if (strcmp(req, HELP) == 0) return help();
    else if (strcmp(req, ASCII) == 0) return ascii();
    else if (strcmp(req, BELL) == 0) return bell();
    else if (strcmp(req, BINARY) == 0) return binary();
    else if (strcmp(req, BYE) == 0) return bye();
    else if (strcmp(req, CLOSE) == 0) return close_cmd();
    else if (strcmp(req, CR) == 0) return cr();
    else if (strcmp(req, DEBUG) == 0) return debug();
    else if (strcmp(req, DISCONNECT) == 0) return disconnect();
    else if (strcmp(req, EXIT) == 0) return exit_cmd();
    else if (strcmp(req, FORM) == 0) return form();
    else if (strcmp(req, GLOB) == 0) return glob();
    else if (strcmp(req, HASH) == 0) return hash();
    else if (strcmp(req, HELP_CLIENT) == 0) return help_client();
    else if (strcmp(req, IMAGE) == 0) return image();
    else if (strcmp(req, MACDEF) == 0) return macdef();
    else if (strcmp(req, VERBOSE) == 0) return verbose();
    else if (strcmp(req, UMASK) == 0) return umask();

    return Faillure;
}

int recvServerReply(char rep[], Asym_Infos* as_infos, Timer* timer)
{
      
}

int handleReply(char rep[], Asym_Infos* as_infos, Timer* timer)
{

}

int handleOption(char option[])
{

}

void callBackTimer(Timer* timer)
{
    errorLog("Time out\n");
}

int main(int argc, char* argvs[])
{
    Asym_Infos as_infos;
    Timer* pubAuthentimer = (Timer*) malloc(sizeof(Timer));
    char option[8];
    char ipaddr[32];
    int sock_fd;
    struct sockaddr_in server_address;
    int opt = 1;
    int addrlen = sizeof(server_address);
    char buffer[BUF_LEN] = {0};
    bool FTPrunning;

    // // Create a FTP socket
    // _socketFTP* socketFTP = (_socketFTP*) malloc(sizeof(_socketFTP));
    // set_socket(socketFTP, sock_fd, &server_address, ipaddr, PORT, addrlen, AF_INET);

    // Initiate a connection with server
    sock_fd = cre_socket();
    end_point(&server_address,ipaddr,PORT);
    connect_endpoint(sock_fd,&server_address,addrlen); 
    
    // public key authen 
    as_infos.setupSocket = sock_fd;
    as_infos.conn = CLIENT;

    setTimer(pubAuthentimer, time(NULL), 30);
    startTimer(pubAuthentimer, callBackTimer);

    if(!public_key_Authentication(&as_infos))
        errorLog("Public key authentication failed\n");
    
    // recv the respond about pubkey authen from server
    recvmsg(as_infos.setupSocket, buffer, 0);

    if(strcmp(buffer, PUB_AUTHEN_FAIL)) 
        errorLog("Public key authentication failed\n");

    // Pub authen done successfully, cancel timer
    cancelTimer(pubAuthentimer);

    FTPrunning = true;

    // Enter into ftp virtual environment
    while(FTPrunning)
    {
        printf("ftp> ");
        fgets(buffer, sizeof(buffer), stdin);
        handleRequest(buffer, &as_infos, (Timer*) malloc(sizeof(Timer)));
    } 
}