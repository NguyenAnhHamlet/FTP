#ifndef __COMMON_DATA__
#define __COMMON_DATA__

#include "common/channel.h"
#include "common/socket_ftp.h"

typedef int (* data_func_ptr) (channel_context*); 
typedef struct 
{
    char command_str[32];
    unsigned int command_code;
    data_func_ptr func ;
} data_command;

int data_conn( channel_context* channel_ctx );
int get(channel_context* channel_ctx);
int put(channel_context* channel_ctx);
int data_append(channel_context* channel_ctx);
int data_newer(channel_context* channel_ctx);
int data_reget(channel_context* channel_ctx);

#endif
