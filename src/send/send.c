#include "send.h"
#include "common.h"
#include "status.h"

int send_msg(unsigned int socket_fd, unsigned int _BUF_LEN, char* msg)
{
    int pos = 0;
    while(_BUF_LEN - pos)
    {
        switch (send(socket_fd, msg, _BUF_LEN, 0))
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

int send_int(unsigned int socket_fd, int num)
{
    int converted_number = htonl(num);
    

    int pos = 0;
    while(sizeof(converted_number) - pos)
    {
        switch (write(socket_fd, &converted_number, sizeof(converted_number)))
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