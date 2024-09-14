#include <sys/select.h> 
#include "receive.h"
#include "common.h"
#include "file.h"
#include "status.h"
#include <errno.h>    

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
