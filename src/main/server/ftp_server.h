#ifndef __SERVER__
#define __SERVER__

#include "cmd.h"
#include "channel.h"

int handleRequestServer(int sockfd, char req[]);

int pass_authen_server(int sockfd, passwd* pw);

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
int case_();
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