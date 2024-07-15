#ifndef __FTP__ 
#define __FTP__

#include <stdio.h>
#include "common.h"
#include "cmd.h"
#include "common/socket_ftp.h"
#include "common/channel.h"

void splitArgs(socket_ftp* socketFTP, int argc, ...);

int handleOp(socket_ftp* socketFTP, char op[]);

int password_authen_client(socket_ftp* c_socket);

// Options functions
void ipv4_op_set(socket_ftp* s_ftp);
void ipv6_op_set(socket_ftp* s_ftp);

int client_data_put(control_channel* c_channel, data_channel* d_channel,
                    socket_ftp* c_socket, socket_ftp* d_socket, 
                    endpoint_type type);

int client_data_get(control_channel* c_channel, data_channel* d_channel);

int client_data_put(control_channel* c_channel, data_channel* d_channel,
                    socket_ftp* c_socket, socket_ftp* d_socket, 
                    endpoint_type type);
                    
int client_data_append(control_channel* c_channel, data_channel* d_channel,
                       endpoint_type type, char* file_name, unsigned int n_len,
                       char* remote_file_name, unsigned int rn_len);

int cd();
int chmod();
int delete_();
int dir();
int lcd();
int ls();
int idle();
int mdelete();
int mdir();
int mget();
int mkdir();
int mls();
int modtime();
int mput();
int newer();
int nlist();
int prompt();
int pwd();
int qc();
int reget();
int rename_();
int reset();
int restart();
int rhelp();
int rmdir();
int rstatus();
int size();
int status();
int system_();
int tick();

#endif