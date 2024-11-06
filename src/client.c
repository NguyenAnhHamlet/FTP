#include "control.h"
#include "common/common.h"
#include <stdbool.h>
#include <stdlib.h>
#include "secure/secure.h"
#include "common/timer.h"
#include <time.h>
#include <signal.h>
#include "common/channel.h"
#include "common/socket_ftp.h"
#include "common/packet.h"
#include "data.h"
#include "control.h"
#include "common/cmd.h"
#include "log/ftplog.h"
#include "algo/algo.h"

#define IPADDR_SIZE  32
#define OPTION_SIZE  8

channel_context channel_ctx;
char name[BUF_LEN];
char pass[BUF_LEN];
bool ftp_running;
control_channel c_channel;
data_channel d_channel;
socket_ftp* c_socket;
socket_ftp* d_socket;
char ipaddr[IPADDR_SIZE];
char option[OPTION_SIZE];
unsigned int iptype;

void client_terminate_connection(control_channel* c_channel);

void handle_init_command(int argc, char* argvs[])
{
    strncpy(ipaddr, argvs[1], IPADDR_SIZE);
    argc > 2 ? strncpy(option, argvs[2], OPTION_SIZE) : memset(option, '\0', OPTION_SIZE); 
    printf("%s\n", ipaddr);
    printf("%s\n", option);
}

int quit() 
{
    ftp_running = 0;
    client_terminate_connection(&c_channel);
}

void time_out_alarm(int sig)
{
    enable_echo();
    fatal("Time out");
}

void signal_handler(int sig)
{
    LOG(CLIENT_LOG, "Received signal %d; terminating.", sig);
    quit();
}

int client_data_put(channel_context* channel_ctx)
{
    return put(channel_ctx);
}

int client_data_get(channel_context* channel_ctx)
{
    return get(channel_ctx);
}

int client_data_append(channel_context* channel_ctx)
{
    return data_append(channel_ctx);
}

int client_change_dir(channel_context* channel_ctx)
{
    return change_dir(channel_ctx);
}

int client_change_mode(channel_context* channel_ctx)
{
    return change_mode(channel_ctx);
}

int client_delete_remote_file(channel_context* channel_ctx)
{
    return delete_remote_file(channel_ctx);
}

int client_list_remote_dir(channel_context* channel_ctx)
{
    return list_remote_dir(channel_ctx);
}

int client_local_change_dir(char* dir, int d_len)
{
    return chdir(dir);
}

int client_list_current_remote_dir(channel_context* channel_ctx)
{
    return list_current_dir(channel_ctx);
}

int client_idle_set_remote(channel_context* channel_ctx)
{
    return idle_set_remote(channel_ctx);
}

int client_remote_mode_time(channel_context* channel_ctx)
{
    return remote_modtime(channel_ctx);
}

int client_data_newer(channel_context* channel_ctx)
{
    return data_newer(channel_ctx);
}

int client_data_reget(channel_context* channel_ctx)
{
    return data_reget(channel_ctx);
}

int client_remote_change_name(channel_context* channel_ctx)
{
    return remote_change_name(channel_ctx);
}

int client_remove_remote_dir(channel_context* channel_ctx)
{
    return remove_remote_dir(channel_ctx);
}

int client_remote_get_size(channel_context* channel_ctx)
{
    return remote_get_size(channel_ctx);
}

void client_terminate_connection(control_channel* c_channel)
{
    control_channel_append_ftp_type(TERMINATE, c_channel);
    control_channel_send(c_channel);
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

int password_authen_client(control_channel* c_channel)
{
    if(!c_channel) return -1;

    memset(name, '\0', BUF_LEN);
    memset(pass, '\0', BUF_LEN);

    // prompt for name
    printf("Name: ");
    if(!fgets(name, BUF_SIZE, stdin))
      fatal("Error reading name\n");

    // prompt for pass 
    disable_echo();
    printf("Pass: ");
    if(!fgets(pass, BUF_SIZE, stdin))
    {
        enable_echo();
        fatal("Error reading pass\n");
    }
    enable_echo();

    // remove newline char
    int len;
    len = strlen(pass); pass[len-1] = '\0';

    control_channel_append_ftp_type(FTP_PASS_AUTHEN, c_channel);
    control_channel_append_str(name, c_channel, strlen(name));
    control_channel_append_str(pass, c_channel, strlen(pass));

    control_channel_send_wait(c_channel);

    if(control_channel_read_expect(c_channel, FTP_ACK) < 1)
    {
      fatal("Pass authenticate failed\n");
      return 0; 
    }

    printf("Pass authenticate succeed\n");
    return 1;

}

int main(int argc, char* argvs[])
{
    char buffer[BUF_LEN];
    unsigned char* request_str;
    unsigned int request_int; 
    unsigned char* cmd;
    unsigned char* arg;
    cipher_context* ctx;

    // init
    request_str = (char*) malloc(BUF_LEN);
    ctx = (cipher_context* ) malloc(sizeof(cipher_context)); 
    aes_cipher_init(ctx);

    // signal and handle
    signal(SIGINT, signal_handler);
    signal(SIGQUIT, signal_handler);
    signal(SIGTERM, signal_handler);

    handle_init_command(argc, argvs);

    // Create a FTP socket
    c_socket = create_ftp_socket(ipaddr, AF_INET, CLIENT, 
                                 PORT_CONTROL, CONTROL, 
                                 cre_socket());
    
    // public key authen 
    control_channel_init_socket_ftp(&c_channel, c_socket, 
                                    c_socket, CLIENT, NULL);

    control_channel_set_time_out(&c_channel, DEFAULT_CHANNEL_TMOUT);

    // set alarm for 30 
    signal(SIGALRM, time_out_alarm);
	   alarm(30);

    if( !public_key_authentication(&c_channel, 0) || 
        !public_key_authentication(&c_channel, 1))
        fatal("Public key authentication failed\n");
    
    // // perform password authentication
    // password_authen_client(&c_channel);

    // Trying to create a shared secret key
    if(!channel_generate_shared_key(&c_channel, ctx))
        fatal("Failed to create a shared secret key\n");

    // password authentication successed, init channel_ctx
    channel_context_init(&channel_ctx, ctx, &d_channel, &c_channel, 
                         c_socket, d_socket, CLIENT);

    // Cancel alarm as all initial steps have been done without any issue
    alarm(0);

    ftp_running = true;

    // Enter into ftp virtual environment
    while(ftp_running)
    {
        printf("ftp> ");
        if(!fgets(buffer, sizeof(buffer), stdin))
        {
            if(feof(stdin))
            {
                printf("EOF signal detected, terminate the program\n");
                return 1;
            }
            else 
            {
                perror("Error reading input");
                continue;
            }
        }

        remove_endline(buffer);
        if(strlen(buffer) == 0) continue; 
        int operation_sucess = 1;
        request_int = get_cmd_contents(buffer, &cmd, &arg);
        
        switch (request_int)
        {
        case CLEAR:
        {
            printf("\033c");
        }
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
            // send GET code to server
            control_channel_append_ftp_type(GET, channel_ctx.c_channel);
            control_channel_send_wait(channel_ctx.c_channel);
            channel_ctx.source = arg;
            channel_ctx.source_len = strlen(arg);
            operation_sucess = client_data_get(&channel_ctx);
            break;
        }
        case PUT:
        {
            // send PUT code to server
            control_channel_append_ftp_type(PUT, channel_ctx.c_channel);
            channel_ctx.source = arg;
            channel_ctx.source_len = strlen(arg);
            operation_sucess = client_data_put(&channel_ctx);
            break;
        }
        case APPEND:
        {
            char* ptr = strchr(arg, ' ');
            *ptr = '\0';
            ptr++;
            // send APPEND code to server
            control_channel_append_ftp_type(APPEND, channel_ctx.c_channel);
            control_channel_send(channel_ctx.c_channel);
            channel_ctx.source = arg;
            channel_ctx.source_len = strlen(arg);
            channel_ctx.source = ptr;
            channel_ctx.source_len = strlen(ptr);
            operation_sucess = client_data_append(&channel_ctx);
            break;
        }
        case NEWER:
        {
            // send NEWER code to server
            control_channel_append_ftp_type(NEWER, channel_ctx.c_channel);
            control_channel_send(channel_ctx.c_channel);
            channel_ctx.source = arg;
            channel_ctx.source_len = strlen(arg);
            operation_sucess = client_data_newer(&channel_ctx);
            break;
        }
        case REGET:
        {
            control_channel_append_ftp_type(REGET, channel_ctx.c_channel);
            control_channel_send(channel_ctx.c_channel);
            channel_ctx.source = arg;
            channel_ctx.source_len = strlen(arg);
            operation_sucess = client_data_reget(&channel_ctx);
            break;
        }
        case CD:
        {
            // send CD code to server
            control_channel_append_ftp_type(CD, channel_ctx.c_channel);
            control_channel_send(channel_ctx.c_channel);
            channel_ctx.source = arg;
            channel_ctx.source_len = strlen(arg);
            operation_sucess = client_change_dir(&channel_ctx);
            break;
        }
        case CHMOD:
        {
            control_channel_append_ftp_type(CHMOD, channel_ctx.c_channel);
            control_channel_send(channel_ctx.c_channel);
            channel_ctx.source = arg;
            channel_ctx.source_len = strlen(arg);
            operation_sucess = client_change_mode(&channel_ctx);
            break;
        }
        case DELETE:
        {
            control_channel_append_ftp_type(DELETE, channel_ctx.c_channel);
            control_channel_send(channel_ctx.c_channel);
            channel_ctx.source = arg;
            channel_ctx.source_len = strlen(arg);
            operation_sucess = client_delete_remote_file(&channel_ctx);
            break;
        }
        case LS:
        {
            char* res = NULL;
            unsigned int r_len;

            control_channel_append_ftp_type(LS, channel_ctx.c_channel);
            control_channel_send(channel_ctx.c_channel);
            channel_ctx.source = arg;
            channel_ctx.source_len = strlen(arg);

            // check if list current dir 
            if(!arg)
                operation_sucess = client_list_current_remote_dir(&channel_ctx);
            else 
                operation_sucess = client_list_remote_dir(&channel_ctx);

            printf("REMOTE DIR:\n");
            printf(GREEN);
            printf("%s", res);
            printf(RESET_COLOR);
            free(res);
            break;
        }
        case MODTIME:
        {
            char modtime[BUF_LEN];
            unsigned int r_len;
            int n_len = strlen(arg);
            memset(modtime, 0, BUF_LEN);
            channel_ctx.source = arg;
            channel_ctx.source_len = strlen(arg);
            channel_ctx.ret = &modtime;
            channel_ctx.source_len = sizeof(modtime);
            control_channel_append_ftp_type(MODTIME, channel_ctx.c_channel);
            control_channel_send(channel_ctx.c_channel);
            operation_sucess = client_remote_mode_time(&channel_ctx);

            printf(GREEN);
            printf("%s\n", modtime);
            printf(RESET_COLOR);

            break;
        }
        case SIZE:
        {
            control_channel_append_ftp_type(SIZE, channel_ctx.c_channel);
            control_channel_send(channel_ctx.c_channel);
            channel_ctx.source = arg;
            channel_ctx.source_len = strlen(arg);
            operation_sucess = client_remote_get_size(&channel_ctx);

            if(operation_sucess)
            {
                printf(GREEN);
                printf("%d\n", channel_ctx.ret_int);
                printf(RESET_COLOR);
            }

            break;
        }
        case RENAME:
        {
            char* ptr = strchr(arg, ' ');
            *ptr = '\0';
            ptr++;
            channel_ctx.source = arg;
            channel_ctx.source_len = strlen(arg);
            channel_ctx.dest = ptr;
            channel_ctx.dest_len = strlen(ptr);
            control_channel_append_ftp_type(RENAME, channel_ctx.c_channel);
            control_channel_send(channel_ctx.c_channel);
            operation_sucess = client_remote_change_name(&channel_ctx);
            break;
        }
        case RMDIR:
        {
            control_channel_append_ftp_type(RMDIR, channel_ctx.c_channel);
            control_channel_send(channel_ctx.c_channel);
            channel_ctx.source = arg;
            channel_ctx.source_len = strlen(arg);
            operation_sucess = client_remove_remote_dir(&channel_ctx);
            break;
        }
        
        default:
            printf("Unknown operation, Abort\n");
            break;
        }

        if(!operation_sucess)
            printf("Operation failed, see log in %s for more infos and retry\n", FTP_CLIENT_LOG_FILE);
    } 

    control_channel_destroy(&c_channel);
    data_channel_destroy(&d_channel);
}
