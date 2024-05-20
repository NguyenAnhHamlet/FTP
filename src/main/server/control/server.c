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

void* pubkeyAuthenThreadFunc(void* vargp)
{
    Asym_Infos as_infos; 
    as_infos.setupSocket = *((int*) vargp);
    if(!public_key_Authentication((Asym_Infos*) vargp))
        LOG("%s %d", "Public key authentication failed on socket", as_infos.setupSocket);
}

int handleRequestServer(int sockfd, char req[])
{

}

int sendRespondServer(int sockfd, char res[])
{

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