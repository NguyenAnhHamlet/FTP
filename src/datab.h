#ifndef __COMMON_DATAB__
#define __COMMON_DATAB__

#include "common/channel.h"
#include "common/socket_ftp.h"

int bget(channel_context* channel_ctx);
int bput(channel_context* channel_ctx);
int bmget(channel_context* channel_ctx);
int bmput(channel_context* channel_ctx);

#endif