#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h> 
#include "secure/secure.h"
#include "log/ftplog.h"
#include "common/timer.h"
#include <signal.h>
#include <fcntl.h>
#include "common/socket_ftp.h"
#include "common/pam.h"
#include "common/packet.h"
#include <pwd.h>
#include "common/cmd.h"
#include "common/file.h"
#include "data.h"
#include "control.h"
#include "algo/algo.h"

socket_ftp* socket_server;

void signal_handler(int sig)
{
    LOG(SERVER_LOG, "Received signal %d; terminating.\n", sig);
    close(socket_server->sockfd);
    exit(255);
}

void time_out_alarm(int sig)
{
    LOG(SERVER_LOG, "Time out\n");
    exit(1);
}

int server_data_conn(channel_context* channel_ctx)
{
    return data_conn(channel_ctx);
}

int server_data_get(channel_context* channel_ctx)
{
    return get(channel_ctx);
}

int server_data_append(channel_context* channel_ctx)
{
    return data_append(channel_ctx);
}

int pass_authen_server(control_channel* c_channel)
{
    struct passwd* pw;
    char data[BUF_LEN];
    char user_name[BUF_LEN];
    char user_pass[BUF_LEN];
    int len;

    if(control_channel_read_expect(c_channel, FTP_PASS_AUTHEN) <= 0)
    {
        LOG(SERVER_LOG, "Failed receive infos name & pass\n");
        return 0;
    }

    len = control_channel_get_data_len_in(c_channel);

    control_channel_get_str(c_channel, data, &len);

    unsigned int index = find_index(data, len, '\n');
    strncpy(user_name, data, index );
    strcpy(user_pass, data + index + 1);

    pw = getpwnam(user_name);

    if (!pw )
    {
      LOG(SERVER_LOG, "Athentication failed for user %s", pw->pw_name);
      return 0;
    }

    start_pam(pw);

    if( auth_pam_password(pw, user_pass))
    {
        control_channel_append_ftp_type(FTP_ACK, c_channel);
    }
    else 
    {
        control_channel_append_ftp_type(FTP_UNACK, c_channel);
    }

    control_channel_send_wait(c_channel);

    return 1;
}

int server_data_put(channel_context* channel_ctx)
{
    return put(channel_ctx);
}

int server_change_dir(channel_context* channel_ctx)
{
    return change_dir(channel_ctx);
}

int server_change_mode(channel_context* channel_ctx)
{
    return change_mode(channel_ctx);
}

int server_delete_remote_file(channel_context* channel_ctx)
{
    return delete_remote_file(channel_ctx);
}

int server_list_remote_dir(channel_context* channel_ctx)
{
    return list_remote_dir(channel_ctx);
}

int server_list_current_remote_dir(channel_context* channel_ctx)
{
    return list_current_dir(channel_ctx);
}

int server_idle_set_remote(channel_context* channel_ctx)
{
    return idle_set_remote(channel_ctx);
}

int server_remote_mode_time(channel_context* channel_ctx)
{
    return remote_modtime(channel_ctx);
}

int server_data_newer(channel_context* channel_ctx)
{
    return data_newer(channel_ctx);
}

int server_data_reget(channel_context* channel_ctx)
{
    return data_reget(channel_ctx);
}

int server_remote_change_name(channel_context* channel_ctx)
{
    return remote_change_name(channel_ctx);
}

int server_remote_get_size(channel_context* channel_ctx)
{
    return remote_get_size(channel_ctx);
}

int server_remove_remote_dir(channel_context* channel_ctx)
{
    return remove_remote_dir(channel_ctx);
}


int main()
{
    socket_server = create_ftp_socket(NULL, AF_INET, SERVER, 
                                      PORT_CONTROL, SERVER_LISTENING, 
                                      cre_socket());
    bool isRunning = 1;
    int pid, newsock;
    unsigned int maxClientSocket = 0;
    unsigned int clientfd;
    fd_set readfds;
    int activity;
    int activity_client;
    pthread_t pub_key_thread;
    char buf[BUF_LEN];

    // signal and handle
    signal(SIGINT, signal_handler);
    signal(SIGQUIT, signal_handler);
    signal(SIGTERM, signal_handler);

    while(isRunning)
    {
        printf("SOCKET: %d\n", socket_server->sockfd);

        // add server socket
        FD_ZERO(&readfds);
        FD_SET(socket_server->sockfd, &readfds);

        activity = select(socket_server->sockfd + 1, &readfds, NULL, NULL, NULL);

        if ((activity < 0) && (errno != EINTR)) 
            perror("select error");

        printf("New connection detected\n");

        if (FD_ISSET(socket_server->sockfd, &readfds))
        {
            newsock = accept_new_connection_ftp(socket_server);

            printf("NEW_SOCK: %d\n", newsock );
            printf("SOCKET_ADDRESS_LEN: %d\n", socket_server->endpoint_addr_size);

            if(newsock < 0 )
            {
                if (errno != EINTR && errno != EWOULDBLOCK)
                {
                    perror("Accept error\n");
                }

                continue;
            }

            if (fcntl(newsock, F_SETFL, 0) < 0) 
            {
                perror("newsock del O_NONBLOCK: %s");
                continue;	
            }

            maxClientSocket = max(newsock, maxClientSocket);

            // New connection from client
            // Fork to form a new process
            if ((pid = fork()) == 0) 
            {
                clientfd = newsock ;
                LOG(SERVER_LOG, "New connection from client with fd: %d\n", clientfd);
                break;
            } 
        }
    }


    // Client process handle
    control_channel c_channel; 
    data_channel d_channel;
    cipher_context* ctx = NULL;
    int time_out = 30 * 60;
    int conn_remain = 1;
    unsigned request_int;
    bool operation_sucess = 1;
    socket_ftp* d_socket;
    socket_ftp* c_socket = socket_ftp_raw_cre();
    channel_context channel_ctx;
    fd_set read_set;

    // init
    ctx = (cipher_context*) malloc(sizeof(cipher_context));

    ftp_socket_cp(c_socket, socket_server);

    control_channel_init(&c_channel, clientfd, clientfd, SERVER, NULL);
    
    signal(SIGALRM, time_out_alarm);
	alarm(30);

    char buf_[4096];

    if(public_key_authentication(&c_channel, 1) == 0 || 
       public_key_authentication(&c_channel, 0) == 0)
    {
        LOG(SERVER_LOG, "Pub authen failed with socket %d\n", c_channel.data_in->in_port);
        exit(1);
    }

    // if(!pass_authen_server(&c_channel))
    //     exit(1);

    // cipher context init for dec/enc of data channel
    aes_cipher_init(ctx);

        // Trying to create a shared secret key
    if(!channel_generate_shared_key(&c_channel, ctx))
        fatal("Failed to create a shared secret key\n");


    // init channel_ctx
    channel_context_init(&channel_ctx, ctx, &d_channel, &c_channel, 
                         c_socket, d_socket, SERVER);
    
    // Cancel alarm as all initial steps are done without issue
    alarm(0);

    while(conn_remain)
    {
        FD_ZERO(&read_set);
        FD_SET(c_channel.data_in->in_port, &read_set);
        select(c_channel.data_in->in_port + 1, &read_set, NULL, NULL, NULL);

        if(control_channel_read_expect(&c_channel, TERMINATE))
        {
            LOG(SERVER_LOG, "Terminate connection with client fd %d", clientfd);
            exit(1);
        }

        request_int = control_channel_get_ftp_type_in(&c_channel);

        printf("CODE: %d\n", request_int);

        switch (request_int)
        {
        case GET:
        {
            char f_name[BUF_LEN];
            unsigned int n_len;
            memset(f_name, 0, BUF_LEN);
            channel_ctx.source = f_name;
            channel_ctx.source_len = sizeof(f_name);
            operation_sucess = server_data_put(&channel_ctx);
            break;
        }
        case PUT:
        {
            char f_name[BUF_LEN];
            unsigned int n_len;
            memset(f_name, 0, BUF_LEN);
            channel_ctx.source = f_name;
            channel_ctx.source_len = sizeof(f_name);
            operation_sucess = server_data_get(&channel_ctx);
            break;
        }
        case APPEND:
        {
            operation_sucess = server_data_append(&channel_ctx);
            break;
        }
        case NEWER:
        {
            char f_name[BUF_LEN];
            unsigned int n_len;    
            channel_ctx.source = f_name;
            channel_ctx.source_len = sizeof(f_name);        
            operation_sucess = server_data_newer(&channel_ctx);
            break;
        }
        case REGET:
        {
            operation_sucess = server_data_reget(&channel_ctx);
            break;
        }
        case CD:
        {
            operation_sucess = server_change_dir(&channel_ctx);
            break;
        }
        case CHMOD:
        {
            operation_sucess = server_change_mode(&channel_ctx);
            break;
        }
        case DELETE:
        {
            operation_sucess = server_delete_remote_file(&channel_ctx);
            break;
        }
        case LS:
        {
            operation_sucess = server_list_remote_dir(&channel_ctx);
            break;
        }
        case MODTIME:
        {
            operation_sucess = server_remote_mode_time(&channel_ctx);
            break;
        }
        case SIZE:
        {
            operation_sucess = server_remote_get_size(&channel_ctx);
            break;
        }
        case RENAME:
        {
            operation_sucess = server_remote_change_name(&channel_ctx);
            break;
        }
        case RMDIR:
        {
            operation_sucess = server_remove_remote_dir(&channel_ctx);
            break;
        }
        
        default:
            printf("Unknown operation\n Abort\n");
            break;
        }

        if(!operation_sucess)
            printf("Operation failed\n");
    }
    
    return 0;
}