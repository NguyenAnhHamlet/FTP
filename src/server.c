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
#include "common/receive.h"
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

int server_data_get(channel_context* channel_ctx, char* file_name, 
                    int* n_len)
{
    return get(channel_ctx, file_name, n_len);
}

int server_data_append(channel_context* channel_ctx, char* file_name, 
                       unsigned int n_len, char* remote_file_name, 
                       unsigned int rn_len)
{
    return data_append(channel_ctx, file_name, n_len, remote_file_name, 
                       rn_len);
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

int server_data_put(channel_context* channel_ctx, 
                    char* file_name, int n_len)
{
    return put(channel_ctx, file_name, n_len);
}

int server_change_dir(control_channel* c_channel, char* dir, int d_len)
{
    return change_dir(c_channel, dir, d_len, SERVER);
}

int server_change_mode(control_channel* c_channel, char* chmod_cmd, int cmd_len)
{
    return change_mode(c_channel, chmod_cmd, cmd_len, SERVER);
}

int server_delete_remote_file(control_channel* c_channel, char* file_name, int n_len)
{
    return delete_remote_file(c_channel, file_name, n_len, SERVER);
}

int server_list_remote_dir(control_channel* c_channel, char* dir, int cmd_len,
                           char* res, unsigned int r_len)
{
    return list_remote_dir(c_channel, dir, cmd_len, res, &r_len, SERVER);
}

int server_list_current_remote_dir(control_channel* c_channel, char* res, 
                                   unsigned int* r_len)
{
    return list_current_dir(c_channel, res, r_len, SERVER);
}

int server_idle_set_remote(control_channel* c_channel, unsigned int* time_out)
{
    return idle_set_remote(c_channel, time_out, SERVER);
}

int server_remote_mode_time(control_channel* c_channel, char* file_name, 
                            unsigned int* n_len, char* modetime, 
                            unsigned int* m_len)
{
    return remote_modtime(c_channel, SERVER, file_name, n_len, modetime, m_len);
}

int server_data_newer(channel_context* channel_ctx, char* file_name, int n_len)
{
    return data_newer(channel_ctx, file_name, n_len);
}

int server_data_reget(channel_context* channel_ctx, char* file_name, int n_len)
{
    return data_reget(channel_ctx, file_name, n_len);
}

int server_remote_change_name(control_channel* c_channel, char* file_name, 
                              int n_len, char* update_name, int u_len)
{
    return remote_change_name(c_channel, file_name, n_len, 
                              update_name, u_len, SERVER);
}

int server_remote_get_size(control_channel* c_channel, char* file_name, int n_len, 
                           unsigned int* file_size)
{
    return remote_get_size(c_channel, file_name, n_len, file_size, SERVER);
}

int server_remove_remote_dir(control_channel* c_channel, char* dir, int d_len)
{
    return remove_remote_dir(c_channel, dir,d_len, SERVER);
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

    if(!pass_authen_server(&c_channel))
        exit(1);

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
        if(control_channel_read_expect(&c_channel, TERMINATE))
        {
            LOG(SERVER_LOG, "Terminate connection with client fd %d", clientfd);
            exit(1);
        }

        request_int = control_channel_get_ftp_type_in(&c_channel);

        switch (request_int)
        {
        case GET:
        {
            char* f_name;
            unsigned int n_len;
            operation_sucess = server_data_put(&channel_ctx, f_name, n_len);
            break;
        }
        case PUT:
        {
            char f_name[BUF_LEN];
            unsigned int n_len;
            memset(f_name, 0, BUF_LEN);
            operation_sucess = server_data_get(&channel_ctx, f_name, &n_len);
            break;
        }
        case APPEND:
        {
            operation_sucess = server_data_append(&channel_ctx,
                                                  NULL, 0, NULL, 0);
            break;
        }
        case NEWER:
        {
            char* f_name;
            unsigned int n_len;
            control_channel_get_str(&c_channel, f_name, &n_len );            
            operation_sucess = server_data_newer(&channel_ctx, f_name, n_len);
            break;
        }
        case REGET:
        {
            char* f_name;
            unsigned int n_len;
            control_channel_get_str(&c_channel, f_name, &n_len ); 
            operation_sucess = server_data_reget(&channel_ctx, f_name, n_len);
            break;
        }
        case CD:
        {
            char* dir;
            unsigned int d_len;
            control_channel_get_str(&c_channel, dir, &d_len ); 
            operation_sucess = server_change_dir(&c_channel, dir, d_len);
            break;
        }
        case CHMOD:
        {
            char* mode;
            unsigned int m_len;
            control_channel_get_str(&c_channel, mode, &m_len ); 
            operation_sucess = server_change_mode(&c_channel, mode, m_len);
            break;
        }
        case DELETE:
        {
            char* f_name;
            unsigned int n_len;
            control_channel_get_str(&c_channel, f_name, &n_len ); 
            operation_sucess = server_delete_remote_file(&c_channel, f_name, n_len);
            break;
        }
        case _DIR:
        {
            char* dir, *res;
            unsigned int d_len, r_len;
            control_channel_get_str(&c_channel, dir, &d_len ); 
            operation_sucess = server_list_remote_dir(&c_channel, dir, d_len, res, r_len);

            break;
        }
        case IDLE:
        {
            unsigned int time_out;
            operation_sucess = idle_set_remote(&c_channel, &time_out, SERVER);
            break;
        }
        case MODTIME:
        {
            char* file_name, *res;
            unsigned int r_len, n_len;
            control_channel_get_str(&c_channel, file_name, &n_len ); 
            operation_sucess = server_remote_mode_time(&c_channel, file_name, &n_len, res, &r_len);

            break;
        }
        case SIZE:
        {
            unsigned int f_size, n_len;
            char* file_name;
            operation_sucess = server_remote_get_size(&c_channel, file_name, n_len, &f_size);

            break;
        }
        case RENAME:
        {
            char* file_name, *update_file_name;
            unsigned int n_len, u_len;
            operation_sucess = server_remote_change_name(&c_channel, file_name, n_len, 
                                                         update_file_name, u_len);
            break;
        }
        case RMDIR:
        {
            char* dir;
            unsigned int d_len;
            operation_sucess = server_remove_remote_dir(&c_channel, dir, d_len);
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