#include "server.h"
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
#include "secure.h"
#include "ftplog.h"
#include "receive.h"
#include "timer.h"
#include <signal.h>
#include <fcntl.h>
#include "socket_ftp.h"
#include "pam.h"
#include "packet.h"
#include <pwd.h>
#include "cmd.h"
#include "file.h"
#include "common/data.h"
#include "control.h"

socket_ftp* socket_server;

void signal_handler(int sig)
{
    LOG("Received signal %d; terminating.", sig);
    close(socket_server->sockfd);
    exit(255);
}

void time_out_alarm(int sig)
{
    LOG("Time out");
    exit(1);
}

int server_data_conn(control_channel* c_channel, data_channel* d_channel,
                    socket_ftp* c_socket, socket_ftp* d_socket, 
                    endpoint_type type)
{
    return data_conn(c_channel, d_channel, c_socket, d_socket, type);
}

int server_data_get(control_channel* c_channel,
                    data_channel* d_channel)
{
    return get(c_channel, d_channel);
}

int server_data_append(control_channel* c_channel, data_channel* d_channel,
                       endpoint_type type, char* file_name, unsigned int n_len,
                       char* remote_file_name, unsigned int rn_len)
{
    return data_append(c_channel, d_channel, SERVER, file_name, 
                       n_len, remote_file_name, rn_len);
}

int pass_authen_server(int sockfd)
{
    Packet* name_packet;
    Packet* pass_packet;
    passwd* pw;
    char* user_name;
    char* user_pass;
    int len;

    packet_read_expect(name_packet, FTP_PASS_AUTHEN);
    packet_get_str(name_packet, user_name, &len);

    pw = getpwnam(user_name);

    if (!pw || !allowed_user(pw))
    {
      LOG("Athentication failed for user %s", pw->pw_name);
      return 0;
    }

    start_pam(pw); 
    packet_read_expect(pass_packet, FTP_PASS_AUTHEN);
    packet_get_str(pass_packet, user_pass, &len);

    return auth_pam_password(pw, user_pass);
  
}

int server_data_put(control_channel* c_channel, data_channel* d_channel,
                    char* file_name, int n_len)
{
    put(c_channel, d_channel, file_name, n_len);
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
    return delete_file(c_channel, file_name, n_len, SERVER);
}

int server_list_remote_dir(control_channel* c_channel, char* dir, int cmd_len,
                           char* res, unsigned int r_len)
{
    return list_remote_dir(c_channel, dir, cmd_len, res, r_len, SERVER);
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

int server_data_newer(control_channel* c_channel, data_channel* d_channel,
                      socket_ftp* c_socket, socket_ftp* d_socket,
                      char* file_name, int n_len)
{
    return data_newer(c_channel, d_channel, c_socket, d_socket, 
                      file_name, n_len, SERVER);
}

int server_data_reget(control_channel* c_channel, data_channel* d_channel,
                      socket_ftp* c_socket, socket_ftp* d_socket,
                      char* file_name, int n_len)
{
    return data_reget(c_channel, d_channel, c_socket, 
                      d_socket, file_name, n_len, SERVER );
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
                                      PORT_CONTROL, CONTROL, 
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
        FD_ZERO(&readfds);

        // add server socket
        FD_SET(socket_server->sockfd, &readfds);

        activity = select(socket_server->sockfd + 1, &readfds, NULL, NULL, NULL);

        if ((activity < 0) && (errno != EINTR)) 
            perror("select error");

        if (FD_ISSET(socket_server->sockfd, &readfds))
        {
            newsock = accept_new_connection_ftp(socket_server);

            if(clientfd < 0 )
            {
                if (errno != EINTR && errno != EWOULDBLOCK)
                  error("Accept error\n");
                continue;
            }

            if (fcntl(newsock, F_SETFL, 0) < 0) 
            {
                error("newsock del O_NONBLOCK: %s", strerror(errno));
                continue;
			      }

            maxClientSocket = max(newsock, maxClientSocket);

            // New connection from client
            // Fork to form a new process
            if ((pid = fork()) == 0) 
            {
                clientfd = newsock ;
                LOG("New connection from client %d", clientfd);
                break;
            } 
        }
    }

    // Client process handle
    control_channel c_channel; 
    data_channel d_channel;
    int time_out = 30 * 60;
    int conn_remain = 1;
    unsigned request_int;
    bool operation_sucess = 1;
    socket_ftp* d_socket;
    socket_ftp* c_socket = create_ftp_socket(NULL, AF_INET, SERVER, 
                                             PORT_CONTROL, SERVER_LISTENING, 
                                             clientfd);

    control_channel_init(&c_channel, clientfd, clientfd, SERVER, -1 );
    
    signal(SIGALRM, time_out_alarm);
		alarm(30);

    if(public_key_authentication(&c_channel, 1) == 0 || 
       public_key_authentication(&c_channel, 0) == 0)
    {
      LOG("Pub authen failed with socket %d\n", clientfd);
      exit(1);
    }

    if(!pass_authen_server(clientfd))
      exit(1);
    
    alarm(0);


    while(conn_remain)
    {
        if(control_channel_read_expect(c_channel, TERMINATE))
        {
            LOG("Terminate connection with client fd %d", clientfd);
            exit(1);
        }

        request_int = control_channel_get_int(c_channel);

        switch (request_int)
        {
        case GET:
        {
            char* f_name;
            unsigned int n_len;
            control_channel_get_str(c_channel, f_name, n_len );
            operation_sucess = server_data_put(c_channel, d_channel, f_name, n_len);
            break;
        }
        case PUT:
        {
            operation_sucess = server_data_get(c_channel, d_channel);
            break;
        }
        case APPEND:
        {
            operation_sucess = server_data_append(c_channel, d_channel, CLIENT, 
                                                  NULL, 0, NULL, 0);
            break;
        }
        case NEWER:
        {
            char* f_name;
            unsigned int n_len;
            control_channel_get_str(c_channel, f_name, &n_len );            
            operation_sucess = server_data_newer(c_channel, d_channel, c_socket, 
                                                 d_socket, f_name, n_len);
            break;
        }
        case REGET:
        {
            char* f_name;
            unsigned int n_len;
            control_channel_get_str(c_channel, f_name, &n_len ); 
            operation_sucess = server_data_reget(c_channel, d_channel, c_socket, 
                                                 d_socket, f_name, n_len);
            break;
        }
        case CD:
        {
            char* dir;
            unsigned int d_len;
            control_channel_get_str(c_channel, dir, &d_len ); 
            operation_sucess = server_change_dir(c_channel, dir, d_len);
            break;
        }
        case CHMOD:
        {
            char* mode;
            unsigned int m_len;
            control_channel_get_str(c_channel, mode, &m_len ); 
            operation_sucess = server_change_mode(c_channel, mode, m_len);
            break;
        }
        case DELETE:
        {
            operation_sucess = client_delete_remote_file(c_channel, arg, strlen(arg));
            break;
        }
        case DIR:
        {
            char* dir, *res;
            unsigned int d_len, r_len;
            control_channel_get_str(c_channel, dir, &d_len ); 
            operation_sucess = server_list_remote_dir(c_channel, dir, d_len, res, r_len);

            break;
        }
        case IDLE:
        {
            unsigned int time_out;
            operation_sucess = idle_set_remote(c_channel, &time_out, SERVER);
            break;
        }
        case MODTIME:
        {
            char* file_name, *res;
            unsigned int r_len, n_len;
            control_channel_get_str(c_channel, file_name, &n_len ); 
            operation_sucess = server_remote_mode_time(c_channel, file_name, &n_len, res, &r_len);

            break;
        }
        case SIZE:
        {
            unsigned int f_size, n_len;
            char* file_name;
            operation_sucess = server_remote_get_size(c_channel, file_name, n_len, &f_size);

            break;
        }
        case RENAME:
        {
            char* file_name, *update_file_name;
            unsigned int n_len, u_len;
            operation_sucess = server_remote_change_name(c_channel, file_name, n_len, 
                                                         update_file_name, u_len)
            break;
        }
        case RMDIR:
        {
            char* dir;
            unsigned int d_len;
            operation_sucess = server_remove_remote_dir(c_channel, dir, d_len);
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