#ifndef __COMMON_DATA__
#define __COMMON_DATA__

#include "channel.h"

int get(control_channel* c_channel, data_channel* d_channel);
int send(control_channel* c_channel, data_channel* d_channel,
         char* file_name, int n_len);

#endif
