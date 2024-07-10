#ifndef __FTP__ 
#define __FTP__

#include <stdio.h>
#include "common.h"
#include "cmd.h"

void splitArgs(socket_ftp* socketFTP, int argc, ...);

int handleOp(socket_ftp* socketFTP, char op[]);

int password_authen_client(socket_ftp* c_socket);

int client_data_conn(control_channel* c_channel, data_channel* d_channel);
int client_data_get(control_channel* c_channel, data_channel* d_channel);

// Options functions
void ipv4_op(socket_ftp* socketFTP);
void ipv6_op(socket_ftp* socketFTP);

int get(control_channel* c_channel, data_channel* d_channel);
int put();
int recv();
int send();

int append();
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