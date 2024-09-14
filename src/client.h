#ifndef __FTP__ 
#define __FTP__

#include <stdio.h>
#include "common/common.h"
#include "common/cmd.h"
#include "common/socket_ftp.h"
#include "common/channel.h"

int handle_option(socket_ftp* s_ftp, unsigned int op);

int password_authen_client(socket_ftp* c_socket);

void ipv4_op_set(socket_ftp* s_ftp);

void ipv6_op_set(socket_ftp* s_ftp);

int quit();

int client_data_put(control_channel* c_channel, data_channel* d_channel,
                    socket_ftp* c_socket, socket_ftp* d_socket, 
                    char* file_name, int n_len, endpoint_type type);

int client_data_get(control_channel* c_channel, data_channel* d_channel, 
                    socket_ftp* c_socket, socket_ftp* d_socket,
                    char* file_name, int n_len, endpoint_type type);

int client_data_put(control_channel* c_channel, data_channel* d_channel,
                    socket_ftp* c_socket, socket_ftp* d_socket, 
                    char* file_name, int n_len, endpoint_type type);
                    
int client_data_append(control_channel* c_channel, data_channel* d_channel,
                       endpoint_type type, char* file_name, unsigned int n_len,
                       char* remote_file_name, unsigned int rn_len);

int client_change_dir(control_channel* c_channel, char* dir, int d_len);

int client_change_mode(control_channel* c_channel, char* chmod_cmd, int cmd_len);

int client_delete_remote_file(control_channel* c_channel, char* file_name, int n_len);

int client_list_remote_dir(control_channel* c_channel, char* dir, int cmd_len,
                           char* res, unsigned int r_len);

int client_local_change_dir(char* dir, int d_len);

int client_list_current_remote_dir(control_channel* c_channel, 
                                   char* res, 
                                   unsigned int* r_len);

int client_idle_set_remote(control_channel* c_channel, unsigned int* time_out);

int client_remote_mode_time(control_channel* c_channel, char* file_name, 
                            unsigned int* n_len, char* modetime, 
                            unsigned int* m_len);

int client_data_newer(control_channel* c_channel, data_channel* d_channel,
                      socket_ftp* c_socket, socket_ftp* d_socket,
                      char* file_name, int n_len);
   
int client_data_reget(control_channel* c_channel, data_channel* d_channel,
                      socket_ftp* c_socket, socket_ftp* d_socket,
                      char* file_name, int n_len);

int client_remote_change_name(control_channel* c_channel, char* file_name, int n_len,
                       char* update_name, int u_len);

int client_remove_remote_dir(control_channel* c_channel, char* dir, int d_len);     

int client_remote_get_size(control_channel* c_channel, char* file_name, int n_len, 
                           unsigned int* file_size);  

void client_terminate_connection(control_channel* c_channel);       

#endif