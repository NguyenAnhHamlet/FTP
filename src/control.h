#ifndef __CONTROL__
#define __CONTROL__

#include "common/channel.h"
#include "control.h"
#include <ftw.h>

#define OS_RELEASE "/etc/os-release"

void operation_abort(control_channel* c_channel);

int remote_file_exist(channel_context* channel_ctx);
int remote_change_dir(channel_context* channel_ctx);
int change_mode(channel_context* channel_ctx);
int delete_remote_file(channel_context* channel_ctx);
int list_remote_dir(channel_context* channel_ctx);
int list_current_dir(channel_context* channel_ctx);
int idle_set_remote(channel_context* channel_ctx);
int remote_modtime(channel_context* channel_ctx);
int local_modtime(char* file_name, unsigned int* n_len, 
                  char* modtime, unsigned int* m_len);
int remote_get_size(channel_context* channel_ctx);
int remote_change_name(channel_context* channel_ctx);
int remove_local_dir(char* dir );
int remove_remote_dir(channel_context* channel_ctx);
int local_get_size(char* file_name, unsigned int* n_len, 
                   unsigned int* file_size);
int list_local_dir(channel_context* channel_ctx);
int mdelte_remote_files(channel_context* channel_ctx);
int remote_mmkdir(channel_context* channel_ctx);
int remote_mkdir(channel_context* channel_ctx);
int mlist_remote_dir(channel_context* channel_ctx);
int local_prompt(channel_context* channel_ctx);
int remote_pwd(channel_context* channel_ctx);
int status(channel_context* channel_ctx);
int remote_system_info(channel_context* channel_ctx);
int passmode(channel_context* channel_ctx);
int local_change_dir(channel_context* channel_ctx);

#endif