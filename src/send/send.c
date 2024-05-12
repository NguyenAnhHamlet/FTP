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
        if(send(_socket_fd, buf, BUF_LEN, 0) <= 0)
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
    if(send(_socket_fd, msg, _BUF_LEN, 0) < 0)
    {
        printf("Sending message error\n");
        return Faillure;
    }

    return Success;
}

int send_int(unsigned int _socket_fd, int num)
{
    int converted_number = htonl(num);

    if(write(_socket_fd, &converted_number, sizeof(converted_number)) <= 0  )
    {
        return Faillure;
    }

    return Success
}