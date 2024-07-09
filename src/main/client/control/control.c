#include "control.h"
#include "send.h"
#include "establish.h"
#include "common.h"
#include <stdbool.h>
#include <stdlib.h>
#include "send.h"
#include "secure.h"
#include "timer.h"
#include <time.h>
#include <signal.h>
#include "channel.h"
#include "socket_ftp.h"
#include "packet.h"

char* name;
char* pass;
bool FTPrunning;


void time_out_alarm(int sig)
{
    fatal("Time out");
}

void splitArgs(socket_ftp* socketFTP, int argc, ...)
{
    va_list ptr;

    va_start(ptr, argc);
    char* arg = va_arg(ptr, char*);
    strcpy(socketFTP->ip_addr, arg);

    for(int i =1; i < argc; i++)
    {
        arg = va_arg(ptr, char*);
        if(!handleOp(socketFTP, arg)) fatal("Faillure in handle options\n"); 
    }
}

int quit() 
{
    FTPrunning = 0;
}

int bell() 
{

}

int bye() 
{
  // Implement bye function here (might be same as quit)
}

int debug() 
{
  // Implement debug function here
}

int disconnect() 
{
  // Implement disconnect function here
}

int form() 
{
  // Implement form function here
}

int help_client() 
{
  // Implement help_client function here
}

int macdef() 
{
  // Implement macdef function here
}

int umask() 
{
  // Implement umask function here
}

// Data command functions
int get(control_channel* channel) 
{
  
}

int put() 
{
  // Implement put function here
}

int recv() 
{
  // Implement recv function here (might be similar to get)
}

int send() 
{
  // Implement send function here (might be similar to put)
}

void ipv4_op(socket_ftp* socketFTP)
{
    socketFTP->endpoint_addr->sin_family = AF_INET;
}

void ipv6_op(socket_ftp* socketFTP)
{
    socketFTP->endpoint_addr->sin_family = AF_INET6;
}

int handleOp(socket_ftp* socketFTP, char op[])
{
    if(strcmp(op, IPV4_OP))         
      ipv4_op(socketFTP);
    else if(strcmp(op, IPV6_OP))    
      ipv6_op(socketFTP);
    else                            
      return 0;

    return 1;
}

void callBackTimer(timer* timer)
{
    fatal("Time out\n");
}

int password_authen_client(socket_ftp* socketFTP)
{
    if(!socketFTP) return -1;

    Packet* packet_name;
    Packet* packet_pass;
    Packet* receive;

    // prompt for name
    printf("Name: ");
    if(!fgets(name, BUF_SIZE, stdin))
      fatal("Error reading name\n");

    // prompt for pass 
    printf("Pass: ");
    if(!fgets(pass, BUF_SIZE, stdin))
      fatal("Error reading name\n");

    Packet* packet = packet_init(packet, socketFTP->sockfd, FTP_PASS_AUTHEN);

    packet_append_str(name, packet_name, BUF_LEN);
    packet_append_str(pass, packet_pass, BUF_LEN);

    packet_send_wait(packet_name);
    packet_send_wait(packet_pass);

    if(packet_read_expect(receive, FTP_ACK) < 1)
    {
      printf("Pass authenticate failed\n");
      return 0; 
    }

    printf("Pass authenticate successed\n");
    return 1;

}

int main(int argc, char* argvs[])
{
    control_channel channel;
    TimerThreadArgs *arg = (TimerThreadArgs*) malloc(sizeof(TimerThreadArgs));
    timer* pubAuthentimer = (timer*) malloc(sizeof(timer));
    char option[8];
    char ipaddr[32];
    char buffer[BUF_LEN];
    unsigned int iptype;

    // Create a FTP socket
    socket_ftp* socketFTP = create_ftp_socket(ipaddr, iptype, CLIENT);
    
    // public key authen 
    control_channel_init(&channel, PORT, PORT, CLIENT, -1);

    // set alarm for 30 seconds
    signal(SIGALRM, time_out_alarm);
		alarm(30);

    if( !public_key_authentication(channel, 0) || 
        !public_key_authentication(channel, 1))
        fatal("Public key authentication failed\n");

    // perform password authentication
    password_authen_client(socketFTP);
    
    // Pub authen done successfully, cancel alarm
    alarm(0);

    FTPrunning = true;

    // Enter into ftp virtual environment
    while(FTPrunning)
    {
        printf("ftp> ");
        fgets(buffer, sizeof(buffer), stdin);
        handleRequest(buffer, &channel, (timer*) malloc(sizeof(timer)));
    } 
}