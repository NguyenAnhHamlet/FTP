#ifndef __SERVER__
#define __SERVER__

#include "cmd.h"
#include "channel.h"

int handleRequestServer(int sockfd, char req[]);

int pass_authen_server(int sockfd, passwd* pw);

int server_data_conn(control_channel* c_channel,
                     data_channel* d_channel,
                     socket_ftp* d_socket)

int server_data_get(control_channel* c_channel,
<<<<<<< HEAD
                    data_channel* d_channel);

=======
                    data_channel* d_channel,
                    socket_ftp* d_socket);

int get();
>>>>>>> 14a728ce950b1f1d31e5c2ca3e3777f82f231bd5
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