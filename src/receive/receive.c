#include <sys/select.h> 
#include "receive.h"
#include "common.h"
#include "file.h"
#include "status.h"

int recv_file(unsigned int _socket_fd, unsigned int _BUF_LEN ,char* _filename, Status_FTP* status)
{
    fd_set read_fds;
    char buf[BUF_LEN];
    FILE* file;
    int byte;

    // The other end-point is on sending operation 
    // There are packages available waiting to be read 
    //  in queue
    while(*status == SEND_START || FD_ISSET(_socket_fd, &read_fds))
    {
        if( byte = recv_msg(_socket_fd, BUF_LEN, buf) >= 0 ) 
            appendFile(_filename,buf,file);
        else 
            break;
    }
    
    if(byte < 0 || *status != SEND_SUCC)
    {
        *status = ABORT;
        return Faillure;
    } 

    return Success;
}

int recv_msg(unsigned int _socket_fd, unsigned int _BUF_LEN, char* msg)
{
    int bytes_received = recv(_socket_fd, msg, _BUF_LEN, SOCK_NONBLOCK);

    if(bytes_received < 0) errorLog("unknown error with socket\n");
    if (bytes_received == 0) errorLog("connection closed by peer\n");

    return bytes_received;
}

int recv_int(unsigned int _socket_fd, int* num)
{
    int received_int = 0;

    if(read(_socket_fd, &received_int, sizeof(received_int)) <= 0)
    {
        return Faillure;
    }

    *num = ntohl(received_int);

    return Success;
}
