#include "send.h"
#include "common.h"
#include "status.h"

int send_file(unsigned int _socket_fd, unsigned int _BUF_LEN ,char* _filename, Status_FTP* status)
{
    FILE* file = fopen(_filename, "rb");
    char buf[BUF_LEN];
    int byte;

    if (file == NULL) 
    {
        // Issue with opening file
        // Abort the operation, mark as unable to open file
        perror("Error opening file");
        *status = FILE_UN;
        exit(EXIT_FAILURE);
    }

    // Start sending operation
    *status = SEND_START;

    while(byte = read(file, buf, BUF_LEN) > 0)
    {
        if(send_msg(_socket_fd, BUF_LEN, buf) == Faillure)
        {
            // Mark as ABORT 
            // Abort the sending operation
            close(file);
            *status = ABORT; 
            errorLog("Fail to send file\n");
        }
    }

    close(file);

    if(byte <= 0) 
    {
        *status = ABORT;
        return Faillure;
    }

    // Sending successfully
    *status = SEND_SUCC;

    return Success;
}

int send_msg(unsigned int _socket_fd, unsigned int _BUF_LEN, char* msg)
{
    int pos = 0;
    while(_BUF_LEN - pos)
    {
        switch (send(_socket_fd, msg, _BUF_LEN, 0))
        {
        case -1 :
            if (errno == EINTR || errno == EAGAIN)
				continue;
            else return Faillure;
        
        default:
            pos += _BUF_LEN;
            break;
        }
    }

    if(pos == _BUF_LEN) return Success;

    return Faillure;
}

int send_int(unsigned int _socket_fd, int num)
{
    int converted_number = htonl(num);
    

    int pos = 0;
    while(sizeof(converted_number) - pos)
    {
        switch (write(_socket_fd, &converted_number, sizeof(converted_number)))
        {
        case -1 :
            if (errno == EINTR || errno == EAGAIN)
				continue;
            else return Faillure;
        
        default:
            pos += _BUF_LEN;
            break;
        }
    }

    if(pos == sizeof(converted_number)) return Success;

    return Faillure;
}