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

socket_ftp* socketServer;

void signal_handler(int sig)
{
    LOG("Received signal %d; terminating.", sig);
    close(socketServer->sockfd);
    exit(255);
}

void time_out_alarm(int sig)
{
    LOG("Time out");
    exit(1);
}

int handleRequestServer(int sockfd, char req[])
{
    
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

int pass_authen_server(int sockfd, passwd* pw)
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

int recvFile() {
  // Implement recvFile function here
}

int sendFile() {
  // Implement sendFile function here
}

// Server side functions
int account() {
  // Implement account function here
}

int append() {
  // Implement append function here
}

int case_() {
  // Implement case_ function here
}

int cd() {
  // Implement cd function here
}

int cdup() {
  // Implement cdup function here
}

int chmod() {
  // Implement chmod function here
}

int delete_() {
  // Implement delete_ function here
}

int dir() {
  // Implement dir function here
}

int ipany() {
  // Implement ipany function here
}

int ipv4() {
  // Implement ipv4 function here
}

int ipv6() {
  // Implement ipv6 function here
}

int lcd() {
  // Implement lcd function here
}

int ls() {
  // Implement ls function here
}

int idle() {
  // Implement idle function here
}

int mdelete() {
  // Implement mdelete function here
}

int mdir() {
  // Implement mdir function here
}

int mget() {
  // Implement mget function here
}

int mkdir() {
  // Implement mkdir function here
}

int mls() {
  // Implement mls function here
}

int mode() {
  // Implement mode function here
}

int modtime() {
  // Implement modtime function here
}

int mput() {
  // Implement mput function here
}

int newer() {
  // Implement newer function here
}

int nlist() {
  // Implement nlist function here
}

int nmap() {
  // Implement nmap function here
}

int ntrans() {
  // Implement ntrans function here
}

int open() {
  // Implement open function here
}

int passive() {
  // Implement passive function here
}

int prompt() {
  // Implement prompt function here
}

int proxy() {
  // Implement proxy function here
}

int pwd() {
  // Implement pwd function here
}

int qc() {
  // Implement qc function here
}

int quit_server() {
  // Implement quit_server function here
}

int quote() {
  // Implement quote function here
}

int reget() {
  // Implement reget function here
}

int rename_() {
  // Implement rename_ function here
}

int reset() {
  // Implement reset function here
}

int restart() {
  // Implement restart function here
}

int rhelp() {
  // Implement rhelp function here
}

int rmdir() {
  // Implement rmdir function here
}

int rstatus() {
  // Implement rstatus function here
}

int runique() {
  // Implement runique function here
}

int sendport() {
  // Implement sendport function here
}

int site() {
  // Implement site function here
}

int size() {
  // Implement size function here
}

int status() {
  // Implement status function here
}

int struct_() {
  // Implement struct_ function here
}

int sunique() {
  // Implement sunique function here
}

int system_() {
  // Implement system_ function here
}

int tenex() {
  // Implement tenex function here
}

int tick() {
  // Implement tick function here
}

int trace() {
  // Implement trace function here
}

int type() {
  // Implement type function here
}

int user() {
  // Implement user function here
}


int main()
{
    socketServer = create_ftp_socket(NULL, AF_INET, SERVER);
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
        FD_SET(socketServer->sockfd, &readfds);

        activity = select(socketServer->sockfd + 1, &readfds, NULL, NULL, NULL);

        if ((activity < 0) && (errno != EINTR)) 
            perror("select error");

        if (FD_ISSET(socketServer->sockfd, &readfds))
        {
            newsock = accept_new_connection_ftp(socketServer);

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
    control_channel channel; 
    control_channel_init(&channel, clientfd, clientfd, SERVER, -1 );
    
    signal(SIGALRM, time_out_alarm);
		alarm(30);

    if(public_key_authentication(&channel, 1) == 0 || 
       public_key_authentication(&channel, 0) == 0)
    {
      LOG("Pub authen failed with socket %d\n", clientfd);
      exit(1);
    }

    if(!pass_authen_server(clientfd))
      exit(1);
    
    alarm(0);
    
    return 0;
}