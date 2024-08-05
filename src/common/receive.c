#include <sys/select.h> 
#include "receive.h"
#include "common.h"
#include "file.h"
#include "status.h"

int recv_msg(unsigned int _socket_fd, unsigned int _BUF_LEN, char* msg)
{
    int pos = 0;
    while(_BUF_LEN - pos)
    {
        switch (recv(_socket_fd, msg, _BUF_LEN, 0))
        {
        case -1 :
        {
            if (errno == EINTR || errno == EAGAIN)
				continue;
            else return Faillure;
            break;
        }
        
        default:
        {
            pos += _BUF_LEN;
            break;
        }
        }
    }

    if(pos == _BUF_LEN) return Success;

    return Faillure;
}

int recv_int(unsigned int _socket_fd, int* num)
{
    int converted_number = htonl(num);

    int pos = 0;
    while(sizeof(converted_number) - pos)
    {
        switch (read(_socket_fd, &converted_number, sizeof(converted_number)))
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
