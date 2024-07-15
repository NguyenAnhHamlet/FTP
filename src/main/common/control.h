#ifndef __CONTROL__
#define __CONTROL__

#include "common/channel.h"

int remote_file_exist(control_channel* c_channel, endpoint_type type,
                      char* file_name, unsigned int n_len);


#endif