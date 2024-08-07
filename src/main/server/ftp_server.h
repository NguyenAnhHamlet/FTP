#ifndef __SERVER__
#define __SERVER__

#include "cmd.h"
#include "channel.h"

int pass_authen_server(int sockfd);

int server_data_conn(control_channel* c_channel, data_channel* d_channel,
                    socket_ftp* c_socket, socket_ftp* d_socket, 
                    endpoint_type type);

int server_data_get(control_channel* c_channel,
                    data_channel* d_channel);

int server_data_put(control_channel* c_channel, data_channel* d_channel,
                    char* file_name, int n_len);

int server_data_append(control_channel* c_channel, data_channel* d_channel,
                       endpoint_type type, char* file_name, unsigned int n_len,
                       char* remote_file_name, unsigned int rn_len);

int server_change_dir(control_channel* c_channel, char* dir, int d_len);

int server_change_mode(control_channel* c_channel, char* chmod_cmd, int cmd_len);

int server_delete_remote_file(control_channel* c_channel, char* file_name, int n_len);

int server_list_remote_dir(control_channel* c_channel, char* dir, int cmd_len,
                           char* res, unsigned int r_len);

int server_list_current_remote_dir(control_channel* c_channel, char* res, 
                                   unsigned int* r_len);

int server_idle_set_remote(control_channel* c_channel, unsigned int* time_out);

int server_data_newer(control_channel* c_channel, data_channel* d_channel,
                      socket_ftp* c_socket, socket_ftp* d_socket,
                      char* file_name, int n_len);
   
int server_data_reget(control_channel* c_channel, data_channel* d_channel,
                      socket_ftp* c_socket, socket_ftp* d_socket,
                      char* file_name, int n_len);

int server_remote_change_name(control_channel* c_channel, char* file_name, int n_len,
                       char* update_name, int u_len); 

int server_remote_get_size(control_channel* c_channel, char* file_name, int n_len, 
                           unsigned int* file_size);   

int server_remove_remote_dir(control_channel* c_channel, char* dir, int d_len);

#endif