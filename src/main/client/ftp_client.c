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
#include "common/data.h"
#include "common/control.h"

char* name;
char* pass;
bool ftp_running;
control_channel c_channel;
data_channel d_channel;
socket_ftp* c_socket;
socket_ftp* d_socket;
char ipaddr[32];
unsigned int iptype;
int lower_case;


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

int client_data_put(control_channel* c_channel, data_channel* d_channel,
                    socket_ftp* c_socket, socket_ftp* d_socket, 
                    endpoint_type type)
{
    return data_conn(c_channel, d_channel, c_socket, d_socket, type);
}

int client_data_get(control_channel* c_channel, data_channel* d_channel)
{
    return get(c_channel, d_channel);
}

int client_data_put(control_channel* c_channel, data_channel* d_channel,
                    char* file_name, int n_len)
{
    return put(c_channel, d_channel, file_name, n_len);
}

int client_data_append(control_channel* c_channel, data_channel* d_channel,
                       endpoint_type type, char* file_name, unsigned int n_len,
                       char* remote_file_name, unsigned int rn_len)
{
    return data_append(c_channel, d_channel, CLIENT, file_name, 
                       n_len, remote_file_name, rn_len);
}

int quit() 
{
    ftp_running = 0;
}

int case_toggle()
{
    lower_case = 1 - lower_case;
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

void ipv4_op_set(socket_ftp* s_ftp)
{
    s_ftp->endpoint_addr->sin_family = AF_INET;
}

void ipv6_op_set(socket_ftp* s_ftp)
{
    s_ftp->endpoint_addr->sin_family = AF_INET6;
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

int password_authen_client(socket_ftp* c_socket)
{
    if(!c_socket) return -1;

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

    Packet* packet = packet_init(packet, c_socket->sockfd, FTP_PASS_AUTHEN);

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
    char option[8];
    char buffer[BUF_LEN];

    // Create a FTP socket
    c_socket = create_ftp_socket(ipaddr, iptype, CLIENT, PORT_CONTROL, CONTROL);
    
    // public key authen 
    control_channel_init_socket_ftp(&c_channel, c_socket, c_socket, CLIENT, -1);

    // set alarm for 30 seconds
    signal(SIGALRM, time_out_alarm);
		alarm(30);

    if( !public_key_authentication(c_channel, 0) || 
        !public_key_authentication(c_channel, 1))
        fatal("Public key authentication failed\n");

    // perform password authentication
    password_authen_client(c_socket);
    
    // Pub authen done successfully, cancel alarm
    alarm(0);

    ftp_running = true;

    // Enter into ftp virtual environment
    while(ftp_running)
    {
        printf("ftp> ");
        fgets(buffer, sizeof(buffer), stdin);
        handleRequest(buffer, &c_channel, (timer*) malloc(sizeof(timer)));
    } 
}
