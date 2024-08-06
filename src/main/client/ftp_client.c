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
#include "cmd.h"

char* name;
char* pass;
bool ftp_running;
control_channel c_channel;
data_channel d_channel;
socket_ftp* c_socket;
socket_ftp* d_socket;
char ipaddr[32];
unsigned int iptype;


void time_out_alarm(int sig)
{
    fatal("Time out");
}

void signal_handler(int sig)
{
    LOG("Received signal %d; terminating.", sig);
    quit();
}

void take_cmd(char* buffer, char* cmd, char* arg)
{
    char* split_ptr;

    if(!split_ptr) 
        return;
    arg = split_ptr;
    
    while(split_ptr = strchr(buffer, ' '))
    {
        *split_ptr = '\0';
        split_ptr++;
    }
}

int client_data_put(control_channel* c_channel, data_channel* d_channel,
                    socket_ftp* c_socket, socket_ftp* d_socket, 
                    char* file_name, int n_len, endpoint_type type)
{
    int res = data_conn(c_channel, d_channel, c_socket, d_socket, type) & 
              put(c_channel, d_channel, file_name, n_len, CLIENT);
    
    return res;
}

int client_data_get(control_channel* c_channel, data_channel* d_channel, 
                    socket_ftp* c_socket, socket_ftp* d_socket,
                    char* file_name, int n_len, endpoint_type type)
{
    int res = data_conn(c_channel, d_channel, c_socket, d_socket, type) &  
              get(c_channel, d_channel, file_name, n_len, CLIENT);
    
    return res;
}

int client_data_append(control_channel* c_channel, data_channel* d_channel,
                       endpoint_type type, char* file_name, unsigned int n_len,
                       char* remote_file_name, unsigned int rn_len)
{
    int res = data_conn(c_channel, d_channel, c_socket, d_socket, type) &  
              data_append(c_channel, d_channel, CLIENT, file_name, 
                          n_len, remote_file_name, rn_len);
    
    return res;
}

int client_change_dir(control_channel* c_channel, char* dir, int d_len)
{
    return change_dir(c_channel, dir, d_len, CLIENT);
}

int client_change_mode(control_channel* c_channel, char* chmod_cmd, int cmd_len)
{
    return change_mode(c_channel, chmod_cmd, cmd_len, CLIENT);
}

int client_delete_remote_file(control_channel* c_channel, char* file_name, int n_len)
{
    return delete_file(c_channel, file_name, n_len, CLIENT);
}

int client_list_remote_dir(control_channel* c_channel, char* dir, int cmd_len,
                           char* res, unsigned int r_len)
{
    return list_remote_dir(c_channel, dir, cmd_len, res, r_len, CLIENT);
}

int client_local_change_dir(char* dir, int d_len)
{
    return chdir(dir);
}

int client_list_current_remote_dir(control_channel* c_channel, char* res, 
                                   unsigned int* r_len)
{
    return list_current_dir(c_channel, res, r_len, CLIENT);
}

int client_idle_set_remote(control_channel* c_channel, unsigned int* time_out)
{
    return idle_set_remote(c_channel, time_out, CLIENT);
}

int client_remote_mode_time(control_channel* c_channel, char* file_name, 
                            unsigned int* n_len, char* modetime, 
                            unsigned int* m_len)
{
    return remote_modtime(c_channel, CLIENT, file_name, n_len, modetime, m_len);
}

int client_data_newer(control_channel* c_channel, data_channel* d_channel,
                      socket_ftp* c_socket, socket_ftp* d_socket,
                      char* file_name, int n_len)
{
    return data_newer(c_channel, d_channel, c_socket, d_socket, 
                      file_name, n_len, CLIENT);
}

int client_data_reget(control_channel* c_channel, data_channel* d_channel,
                      socket_ftp* c_socket, socket_ftp* d_socket,
                      char* file_name, int n_len)
{
    return data_reget(c_channel, d_channel, c_socket, 
                      d_socket, file_name, n_len, CLIENT );
}

int client_remote_change_name(control_channel* c_channel, char* file_name, 
                              int n_len, char* update_name, int u_len)
{
    return remote_change_name(c_channel, file_name, n_len, 
                              update_name, u_len, CLIENT);
}

int client_remove_remote_dir(control_channel* c_channel, char* dir, int d_len)
{
    return client_remove_remote_dir(c_channel, dir, d_len);
}

int client_remote_get_size(control_channel* c_channel, char* file_name, int n_len, 
                           unsigned int* file_size)
{
    return remote_get_size(c_channel, file_name, n_len, file_size, CLIENT);
}

void client_terminate_connection(control_channel* c_channel)
{
    control_channel_append_ftp_type(TERMINATE, c_channel);
    control_channel_send(c_channel);
}

int quit() 
{
    ftp_running = 0;
    client_terminate_connection(&c_channel);
}

void ipv4_op_set(socket_ftp* s_ftp)
{
    s_ftp->endpoint_addr->sin_family = AF_INET;
}

void ipv6_op_set(socket_ftp* s_ftp)
{
    s_ftp->endpoint_addr->sin_family = AF_INET6;
}

int handle_option(socket_ftp* s_ftp, unsigned int op)
{
    switch (op)
    {
    case IPV4_OP:
        ipv4_op_set(s_ftp);
        break;
    case IPV6_OP:
        ipv6_op_set(s_ftp);
    default:
        break;
    }
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
    unsigned char* request_str; 
    unsigned int request_int;
    unsigned char* arg;

    // signal and handle
    signal(SIGINT, signal_handler);
    signal(SIGQUIT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Create a FTP socket
    c_socket = create_ftp_socket(ipaddr, iptype, CLIENT, PORT_CONTROL, CONTROL, cre_socket());
    
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
        take_cmd(buffer, request_str, arg);
        request_int = get_cmd(request_str);
        int operation_sucess = 1;
        
        switch (request_int)
        {
        case IPV4_OP:
        {
            operation_sucess = handle_option(c_socket, IPV4_OP);
            break;
        }
        case IPV6_OP:
        {
            operation_sucess = handle_option(c_socket, IPV6_OP);
            break;
        }
        case GET:
        {
            operation_sucess = client_data_get(c_channel, d_channel, c_socket, 
                                               d_socket, arg, strlen(arg), CLIENT);
            break;
        }
        case PUT:
        {
            operation_sucess = client_data_put(c_channel, d_channel, c_socket, 
                                               d_socket, arg, strlen(arg), CLIENT);
            break;
        }
        case APPEND:
        {
            operation_sucess = client_data_append(c_channel, d_channel, CLIENT, 
                                                  arg, strlen(arg), strchr(arg, '\0')++, 
                                                  strlen(strchr(arg, '\0')++));
            break;
        }
        case NEWER:
        {
            operation_sucess = client_data_newer(c_channel, d_channel, c_socket, 
                                                 d_socket, arg, strlen(arg));
            break;
        }
        case REGET:
        {
            operation_sucess = client_data_reget(c_channel, d_channel, c_socket, 
                                                 d_socket, arg, strlen(arg));
            break;
        }
        case CD:
        {
            operation_sucess = client_change_dir(c_channel, arg, strlen(arg));
            break;
        }
        case CHMOD:
        {
            operation_sucess = client_change_mode(c_channel, arg, strlen(arg));
            break;
        }
        case DELETE:
        {
            operation_sucess = client_delete_remote_file(c_channel, arg, strlen(arg));
            break;
        }
        case DIR:
        {
            char* res;
            unsigned int r_len;
            operation_sucess = client_list_remote_dir(c_channel, arg, strlen(arg), res, &r_len);

            if (operation_sucess) 
                printf("%s\n", res);

            break;
        }
        case IDLE:
        {
            operation_sucess = idle_set_remote(c_channel, to_int(arg), CLIENT);
            break;
        }
        case MODTIME:
        {
            char* res;
            unsigned int r_len;

            operation_sucess = client_remote_mode_time(c_channel, arg, strlen(arg), res, &r_len);

            if (operation_sucess) 
                printf("%s\n", res);

            break;
        }
        case SIZE:
        {
            unsigned int f_size;

            operation_sucess = client_remote_get_size(c_channel, arg, 
                                                      strlen(arg), &f_size);

            if(operation_sucess)
                printf("%d\n", f_size);

            break;
        }
        case RENAME:
        {
            operation_sucess = client_remote_change_name(c_channel, arg, strlen(arg), 
                                                         strchr(arg, '\0')++, 
                                                         strlen(strchr(arg, '\0')++))
            break;
        }
        case RMDIR:
        {
            operation_sucess = client_remove_remote_dir(c_channel, arg, strlen(arg));
            break;
        }
        
        default:
            printf("Unknown operation\n Abort\n");
            break;
        }

        if(!operation_sucess)
            printf("Operation failed\n Retry\n");
    } 

    control_channel_destroy(&c_channel);
    data_channel_destroy(&d_channel);
}
