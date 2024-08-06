#ifndef __CONTROL__
#define __CONTROL__

#include "common/channel.h"
#include "common/control.h"

void operation_abort(control_channel* c_channel);

int remote_file_exist(control_channel* c_channel, endpoint_type type,
                      char* file_name, unsigned int n_len);
int change_dir(control_channel* c_channel, char* dir, int d_len,
               endpoint_type type);
int change_mode(control_channel* c_channel, char* chmod_cmd, int cmd_len,
                endpoint_type type);
int delete_file(control_channel* c_channel, char* file_name, 
                unsigned int n_len, endpoint_type type );
int list_remote_dir(control_channel* c_channel, char* dir, int cmd_len,
                    char* res, unsigned int* r_len, endpoint_type type);
int list_current_dir(control_channel* c_channel, char* res, 
                     unsigned int* r_len, endpoint_type type);
int idle_set_remote(control_channel* c_channel, unsigned int* time_out, 
                    endpoint_type type);
int remote_modtime(control_channel* c_channel, endpoint_type type, 
                    char* file_name, unsigned int* n_len, char* modetime, 
                    unsigned int* m_len);
int local_modtime(char* file_name, unsigned int* n_len, 
                  char* modtime, unsigned int* m_len);
int local_get_size(char* file_name, unsigned int* n_len, 
                   unsigned int* file_size);
int remote_get_size(control_channel* c_channel, char* file_name, int n_len, 
                    unsigned int* file_size, endpoint_type type);
int remote_change_name(control_channel* c_channel, char* file_name, int n_len,
                       char* update_name, int u_len, endpoint_type type);
int unlink_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf);
int remove_local_dir(char* dir );
int remove_remote_dir(control_channel* c_channel, char* dir, int d_len, endpoint_type type );

#endif