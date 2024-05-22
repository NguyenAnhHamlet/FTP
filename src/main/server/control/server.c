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

void callbackPubAuthen(TimerThreadArgs* arg)
{
    close(arg->socketfd);
    cancelTimerThread(arg);
}

void* pubkeyAuthenThreadFunc(void* vargp)
{
    Timer* pubAuthentimer = (Timer*)malloc(sizeof(Timer));
    TimerThreadArgs* arg = (TimerThreadArgs*) malloc(sizeof(TimerThreadArgs));
    setTimer(pubAuthentimer, time(NULL), 30);
    startTimerThread(   (TimerThreadArgs*) malloc(sizeof(TimerThreadArgs)), 
                        pubAuthentimer, callbackPubAuthen);
    Asym_Infos as_infos; 
    as_infos.setupSocket = *((int*) vargp);
    if(!public_key_Authentication((Asym_Infos*) vargp))
    {
        LOG("%s %d", "Public key authentication failed on socket", as_infos.setupSocket);
        cancelTimerThread(arg);
    }
}

int handleRequestServer(int sockfd, char req[])
{
    
}


int get() {
  // Implement get function here
}

int put() {
  // Implement put function here
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
    _socketFTP* socket = cre_FTPSocket(NULL, AF_INET, SERVER);
    bool isRunning = 1;
    unsigned int maxClientSocket = 0;
    unsigned int clientfd;
    fd_set readfds;
    int activity;
    int activity_client;
    Asym_Infos as_infos; 
    pthread_t pub_key_thread;
    char buf[BUF_LEN];

    while(isRunning)
    {
        FD_ZERO(&readfds);

        // add server socket
        FD_SET(socket->sockfd, &readfds);

        // add client sockets
        for(int i =0; i< maxClientSocket; i++)
        {
            FD_SET(i, &readfds);
        }

        activity = select(socket->sockfd + 1, &readfds, NULL, NULL, NULL);

        if ((activity < 0) && (errno != EINTR)) 
            perror("select error");

        if (FD_ISSET(socket->sockfd, &readfds))
        {
            clientfd = accept_New_ConnectionFTP(socket);
            maxClientSocket = max(clientfd, maxClientSocket);
            
            pthread_create(&pub_key_thread, NULL, pubkeyAuthenThreadFunc, (void*) &clientfd);
        }

        activity_client = select(maxClientSocket + 1, &readfds, NULL, NULL, NULL);

        if(activity_client)
        {
            for(int i=0 ; i<= maxClientSocket; i++)
            {
                if (FD_ISSET(i, &readfds))
                {   
                    recv_msg(i, BUF_LEN, buf);
                    handleRequestServer(i, buf);
                }
            }
        }   
    }

    return 0;
}