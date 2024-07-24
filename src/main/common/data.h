#ifndef __COMMON_DATA__
#define __COMMON_DATA__

#include "channel.h"
#include "socket_ftp.h"

int data_conn(control_channel* c_channel, data_channel* d_channel,
              socket_ftp* c_socket, socket_ftp* d_socket, 
              endpoint_type type );
int get(control_channel* c_channel, data_channel* d_channel,
        char* file_name, int* n_len, endpoint_type type);
int put(control_channel* c_channel, data_channel* d_channel,
        char* file_name, int n_len, endpoint_type type);
int data_append(control_channel* c_channel, data_channel* d_channel,
                endpoint_type type, char* file_name, unsigned int n_len,
                char* remote_file_name, unsigned int rn_len);
int data_newer(control_channel* c_channel, data_channel* d_channel,
               socket_ftp* c_socket, socket_ftp* d_socket,
               char* file_name, int n_len, endpoint_type type);
int data_reget(control_channel* c_channel, data_channel* d_channel,
               socket_ftp* c_socket, socket_ftp* d_socket,
               char* file_name, int n_len, endpoint_type type);

#endif
