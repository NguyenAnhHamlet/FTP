#include "control.h"
#include "common/common.h"
#include "common/ftp_type.h"
#include "cmd.h"
#include "common/channel.h"
#include "log/ftplog.h"
#include <string.h>
#include "common/file.h"
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ftw.h>

void operation_abort(control_channel* c_channel)
{
    control_channel_append_ftp_type(ABORT, c_channel);
    control_channel_send(c_channel);
}

int remote_file_exist(channel_context* channel_ctx)
{
    switch (channel_ctx->type)
    {
    case CLIENT:
    {
        control_channel_append_ftp_type(ASK_FILE_EXIST, channel_ctx->c_channel);
        control_channel_send(channel_ctx->c_channel);
        if(!control_channel_read_expect(channel_ctx->c_channel, FILE_EXIST))
        {
            LOG(CLIENT_LOG, "File %s does not exist\n", channel_ctx->source);
            operation_abort(channel_ctx->c_channel);
            return 0;
        }

        LOG(CLIENT_LOG, "File %s exist, start appending file to remote\n", 
            channel_ctx->source);

        break;
    }
    
    case SERVER:
    {
        char* file_name;
        int n_len;

        if(!control_channel_read_expect(channel_ctx->c_channel, ASK_FILE_EXIST))
        {
            LOG(SERVER_LOG, "Not expected this code number %d\n", 
                channel_ctx->c_channel->data_in->p_header->packet_type);
            
            return 0;
        }

        LOG(SERVER_LOG, 
            "Receive code number %d\n Start checking file existence\n",
            channel_ctx->c_channel->data_in->p_header->packet_type);

        control_channel_get_str(channel_ctx->c_channel, file_name, &n_len);

        if(not_exist(file_name))
            control_channel_append_int(FILE_NOT_EXIST, channel_ctx->c_channel);
        else 
            control_channel_append_int(FILE_EXIST, channel_ctx->c_channel);

        control_channel_send(channel_ctx->c_channel);

        break;
    }

    default:
    {
        operation_abort(channel_ctx->c_channel);
        return -1;
    }

    }

    return 1;
}

int change_dir(channel_context* channel_ctx)
{
    switch (channel_ctx->type)
    {
    case CLIENT:
    {
        control_channel_append_ftp_type(CD, channel_ctx->c_channel);
        control_channel_append_str(channel_ctx->source, 
                                   channel_ctx->c_channel, channel_ctx->source_len);
        control_channel_send(channel_ctx->c_channel);

        if(!control_channel_read_expect(channel_ctx->c_channel, SUCCESS))
        {
            LOG(CLIENT_LOG, "Fail to change dir\n");
            operation_abort(channel_ctx->c_channel);
            return 0;
        }

        LOG(CLIENT_LOG, "Successfully changed remote dir to %s\n", channel_ctx->source);

        break;
    }
    case SERVER:
    {
        char dir[BUF_LEN];
        char cur_dir[BUF_LEN];
        char abs_dir[BUF_LEN];
        int d_len;

        memset(dir, 0, BUF_LEN);
        memset(cur_dir, 0, BUF_LEN);

        if(!control_channel_read_expect(channel_ctx->c_channel, CD))
        {
            LOG(SERVER_LOG, "Unknown option\n");
            operation_abort(channel_ctx->c_channel);
            return 0;
        }

        control_channel_get_str(channel_ctx->c_channel, dir, &d_len);
        x_abs_path(dir, abs_dir);
        x_chdir(dir);
        x_getcwd(cur_dir);

        if(strcmp(abs_dir, cur_dir))
        {
            LOG(SERVER_LOG, "Change dir failed, current dir is: %s , expected %s\n", cur_dir, abs_dir);
            operation_abort(channel_ctx->c_channel);
            return 0;
        }

        LOG(SERVER_LOG, "Change dir done, current dir: %s\n", cur_dir);
        control_channel_append_ftp_type(SUCCESS, channel_ctx->c_channel);
        control_channel_send(channel_ctx->c_channel);

        break;
    }
    
    default:
    {
        operation_abort(channel_ctx->c_channel);
        return 0;
    }

    }

    return 1;
}

int change_mode(channel_context* channel_ctx)
{
    switch (channel_ctx->type)
    {
    case CLIENT:
    {
        control_channel_append_ftp_type(CHMOD, channel_ctx->c_channel);
        control_channel_append_str(channel_ctx->source, channel_ctx->c_channel, 
                                   channel_ctx->source_len);
        control_channel_send(channel_ctx->c_channel);

        if(!control_channel_read_expect(channel_ctx->c_channel, SUCCESS))
        {
            LOG(CLIENT_LOG, "Failed to change mode, CODE received : %d\n", control_channel_get_ftp_type_in(channel_ctx->c_channel));
            operation_abort(channel_ctx->c_channel);
            return 0;
        }

        LOG(CLIENT_LOG, "Done change mode\n");

        break;
    }
    case SERVER:
    {
        char* file_name;
        char* mode = NULL;
        char* token = NULL;
        int no = 0 ;

        int data_len = control_channel_get_data_len_in(channel_ctx->c_channel) + 1;
        channel_ctx->source = (char*) malloc(data_len);
        memset(channel_ctx->source, 0 , data_len);

        if(!control_channel_read_expect(channel_ctx->c_channel, CHMOD))
        {
            LOG(SERVER_LOG, "Did not receive CHMOD code but %d instead\n", 
                control_channel_get_ftp_type_in(channel_ctx->c_channel));
            return 0;
        }

        control_channel_get_str(channel_ctx->c_channel, channel_ctx->source, 
                                &channel_ctx->source_len);
        LOG(SERVER_LOG, "CHMOD CMD: %s\n", channel_ctx->source);
        mode = channel_ctx->source;
        while(token = strchr(channel_ctx->source, ' '))
        {
            file_name = channel_ctx->source + (token - channel_ctx->source) + 1;
            *token = 0;
            token++;
            LOG(SERVER_LOG, "file_name: %s\n", file_name);
            LOG(SERVER_LOG, "mode: %s\n", mode);
        }

        if(chmod(file_name, strtol(mode, 0, 8)) < 0)
        {
            LOG(SERVER_LOG, "Fail to change mode\n");
            operation_abort(channel_ctx->c_channel);
            return 0;
        }

        LOG(SERVER_LOG, "Change mode file done\n");
        control_channel_append_ftp_type(SUCCESS, channel_ctx->c_channel);
        control_channel_send(channel_ctx->c_channel);

        free(channel_ctx->source);

        break;
    }

    default:
    {
        operation_abort(channel_ctx->c_channel);
        return 0;
    }

    }

    return 1;
}

int delete_remote_file(channel_context* channel_ctx)
{
    switch (channel_ctx->type)
    {
    case CLIENT:
    {
        control_channel_append_ftp_type(DELETE, channel_ctx->c_channel);
        control_channel_append_str(channel_ctx->source, channel_ctx->c_channel,
                                   channel_ctx->source_len);
        control_channel_send(channel_ctx->c_channel);

        if(!control_channel_read_expect(channel_ctx->c_channel, SUCCESS))
        {
            LOG(CLIENT_LOG, "Delete remote file failed, received CODE: %d\n", 
                control_channel_get_ftp_type_in(channel_ctx->c_channel));
            operation_abort(channel_ctx->c_channel);
            return 0;
        }

        LOG(CLIENT_LOG, "Delete remote file done\n");
        break;
    }
    case SERVER:
    {
        if(!control_channel_read_expect(channel_ctx->c_channel, DELETE))
        {
            LOG(SERVER_LOG, "Unknown option\n");
            operation_abort(channel_ctx->c_channel);

            return 0;
        }

        int data_len = control_channel_get_data_len_in(channel_ctx->c_channel) + 1;
        channel_ctx->source = (char*) malloc(data_len);
        control_channel_get_str(channel_ctx->c_channel, channel_ctx->source, 
                                &channel_ctx->source_len);

        if(remove(channel_ctx->source))
        {
            LOG(SERVER_LOG, "Delete file %s failed\n", channel_ctx->source);
            operation_abort(channel_ctx->c_channel);
            return 0;
        }

        LOG(SERVER_LOG, "Delete file %s done\n", channel_ctx->source);
        control_channel_append_ftp_type(SUCCESS, channel_ctx->c_channel);
        control_channel_send(channel_ctx->c_channel);

        free(channel_ctx->source);

        break;
    }
    
    default:
    {
        operation_abort(channel_ctx->c_channel);
        return -1;
    }

    }

    return 1;
}

int list_remote_dir(channel_context* channel_ctx)
{
    switch (channel_ctx->type)
    {
    case CLIENT:
    {
        control_channel_append_ftp_type(LS, channel_ctx->c_channel);
        control_channel_append_str(channel_ctx->source, channel_ctx->c_channel, 
                                   channel_ctx->source_len);
        control_channel_send(channel_ctx->c_channel);

        if(!control_channel_read_expect(channel_ctx->c_channel, LS))
        {
            LOG(CLIENT_LOG, "Failed to list dir, received CODE: %d\n", 
                control_channel_get_ftp_type_in(channel_ctx->c_channel));

            return 0;
        }

        int data_len = control_channel_get_data_len_in(channel_ctx->c_channel) + 1;
        char* data = (char*) malloc(data_len);
        channel_ctx->ret = data;
        channel_ctx->ret_len= data_len;
        control_channel_get_str(channel_ctx->c_channel, channel_ctx->ret, 
                                &channel_ctx->ret_len);

        break;
    }
    case SERVER:
    {
        char* res = (char*) malloc(BUF_LEN);
        unsigned int ret_len;
        memset(res, 0, BUF_LEN);

        if(!control_channel_read_expect(channel_ctx->c_channel, LS))
        {
            LOG(SERVER_LOG, "Failed to list dir, received CODE: %d\n", 
                control_channel_get_ftp_type_in(channel_ctx->c_channel));
            operation_abort(channel_ctx->c_channel);

            return 0;
        }

        int data_len = control_channel_get_data_len_in(channel_ctx->c_channel) + 1;
        channel_ctx->source = (char*) malloc(data_len);
        memset(channel_ctx->source, 0, data_len);

        control_channel_get_str(channel_ctx->c_channel, channel_ctx->source, 
                                &channel_ctx->source_len);                       
        
        if(!list_dir(channel_ctx->source, res, &ret_len))
        {
            LOG(SERVER_LOG, "List dir %s failed\n", channel_ctx->source);
            operation_abort(channel_ctx->c_channel);
            free(res);
            return 0;
        }

        control_channel_append_ftp_type(LS, channel_ctx->c_channel);
        control_channel_append_str(res, channel_ctx->c_channel, ret_len);
        control_channel_send(channel_ctx->c_channel);

        free(res);
        free(channel_ctx->source);

        break;
    }
    
    default:
    {
        operation_abort(channel_ctx->c_channel);
        return -1;
    }

    }

    return 1;
}

int list_current_dir(channel_context* channel_ctx )
{
    char dir[2];
    memset(dir, 0 , 2);
    strncpy(dir, ".", 1);
    channel_ctx->source = dir;
    channel_ctx->source_len = 2;
    return list_remote_dir(channel_ctx);
}

int idle_set_remote(channel_context* channel_ctx)
{
    switch (channel_ctx->type)
    {
    case CLIENT:
    {
        control_channel_append_header(channel_ctx->c_channel, 0, sizeof(Packet), 
                                      0, IDLE, 0, 0);
        control_channel_append_int( (int) *channel_ctx->source, channel_ctx->c_channel );
        if(!control_channel_send(channel_ctx->c_channel) || 
           !control_channel_read_expect(channel_ctx->c_channel, SUCCESS))
        {
            LOG(CLIENT_LOG, "Set timeout remote failed\n");
            operation_abort(channel_ctx->c_channel);

            return 0;
        }

        break;
    }
    case SERVER:
    {
        if(!control_channel_read_expect(channel_ctx->c_channel, IDLE))
        {
            LOG(SERVER_LOG, "Unknown option\n");
            operation_abort(channel_ctx->c_channel);

            return 0;
        }

        channel_ctx->ret_int = control_channel_get_int(channel_ctx->c_channel);

        break;
    }

    default:
    {
        operation_abort(channel_ctx->c_channel);
        return -1;
    }

    }
}

int remote_modtime(channel_context* channel_ctx)
{
    switch (channel_ctx->type)
    {
    case CLIENT :
    {
        control_channel_append_ftp_type(MODTIME, channel_ctx->c_channel);
        control_channel_append_str(channel_ctx->source, channel_ctx->c_channel, 
                                   channel_ctx->source_len);
        control_channel_send_wait(channel_ctx->c_channel);
        
        if(!control_channel_read_expect(channel_ctx->c_channel, MODTIME))
        {
            LOG(CLIENT_LOG, "Could not get mod time of remote file\n"); 
            operation_abort(channel_ctx->c_channel);

            return 0;
        }

        int data_len = control_channel_get_data_len_in(channel_ctx->c_channel) + 1;
        char* data = (char*) malloc(data_len);
        channel_ctx->ret = data;

        control_channel_get_str(channel_ctx->c_channel, channel_ctx->ret,
                                &channel_ctx->ret_len);

        break;
    }
    
    case SERVER:
    {
        struct stat attrib;
        char file_name[BUF_LEN];
        int f_len; 
        char modetime[BUF_LEN];

        // init
        memset(file_name, 0, BUF_LEN);
        memset(modetime, 0, BUF_LEN);

        if(!control_channel_read_expect(channel_ctx->c_channel, MODTIME))
        {
            LOG(SERVER_LOG, "Unknown CODE from client side," 
                "received CODE %d: \n",
                control_channel_get_ftp_type_in(channel_ctx->c_channel));
            operation_abort(channel_ctx->c_channel);
            return 0;
        }

        control_channel_get_str(channel_ctx->c_channel, file_name, &f_len);
        stat(file_name, &attrib);
        strftime(modetime, 50, "%Y-%m-%d %H:%M:%S", 
                 localtime(&attrib.st_mtime));

        control_channel_append_ftp_type(MODTIME, channel_ctx->c_channel);
        control_channel_append_str(modetime, channel_ctx->c_channel, strlen(modetime));
        control_channel_send(channel_ctx->c_channel);

        break;
    }

    default:
    {
        operation_abort(channel_ctx->c_channel);
        return -1;
    }

    }

    return 1;
}

int local_modtime(char* file_name, unsigned int* n_len, 
                  char* modtime, unsigned int* m_len)
{
    struct stat attrib;
    stat(file_name, &attrib);
    strftime(modtime, 50, "%Y-%m-%d %H:%M:%S", localtime(&attrib.st_mtime));  
}

int local_get_size(char* file_name, unsigned int* n_len, 
                   unsigned int* file_size)
{
    struct stat attrib;
    stat(file_name, &attrib);

    *file_size = attrib.st_size;

    return *file_size;
}

int remote_get_size(channel_context* channel_ctx)
{
    switch (channel_ctx->type)
    {
    case CLIENT :
    {
        control_channel_append_ftp_type(SIZE, channel_ctx->c_channel);
        control_channel_append_str(channel_ctx->source, channel_ctx->c_channel, 
                                   channel_ctx->source_len);
        control_channel_send(channel_ctx->c_channel);

        if(!control_channel_read_expect(channel_ctx->c_channel, SIZE))
        {
            LOG(CLIENT_LOG, "Unknown CODE from server side," 
                "received CODE %d: \n",
                control_channel_get_ftp_type_in(channel_ctx->c_channel));
            operation_abort(channel_ctx->c_channel);

            return 0;
        }

        channel_ctx->ret_int = control_channel_get_int(channel_ctx->c_channel);

        break;
    }
    
    case SERVER:
    {
        struct stat attrib;

        if(!control_channel_read_expect(channel_ctx->c_channel, SIZE))
        {
            LOG(SERVER_LOG, "Unknown CODE from client side," 
                "received CODE %d: \n",
                control_channel_get_ftp_type_in(channel_ctx->c_channel));
            operation_abort(channel_ctx->c_channel);

            return 0;
        }

        int data_len = control_channel_get_data_len_in(channel_ctx->c_channel) + 1;
        channel_ctx->source = (char*) malloc(data_len);
        memset(channel_ctx->source, 0, data_len);

        control_channel_get_str(channel_ctx->c_channel, channel_ctx->source, 
                                &channel_ctx->source_len);
        stat(channel_ctx->source, &attrib);
        control_channel_append_ftp_type(SIZE, channel_ctx->c_channel);
        control_channel_append_int(attrib.st_size, channel_ctx->c_channel);
        control_channel_send_wait(channel_ctx->c_channel);
        free(channel_ctx->source);

        break;
    }

    default:
    {
        operation_abort(channel_ctx->c_channel);
        return -1;
    }

    }

    return 1;
}

int remote_change_name(channel_context* channel_ctx)
{
    switch (channel_ctx->type)
    {
    case CLIENT:
    {
        // Update design 
        // Read and seperate the arg into local_name and remote_name
        char* old_name = channel_ctx->source;
        char* new_name = strchr(channel_ctx->source, ' ');
        if(!new_name)
        {
            LOG(CLIENT_LOG, "arguments lack remote_name, it contains only %s\n",
                channel_ctx->source);
            return 0;
        }

        *new_name = 0;
        new_name++;

        LOG(CLIENT_LOG, "file name: %s %s\n", old_name, new_name);

        control_channel_append_ftp_type(RENAME, channel_ctx->c_channel);
        control_channel_append_str(old_name, channel_ctx->c_channel, 
                                   strlen(old_name));
        control_channel_append_str(" ", channel_ctx->c_channel, 1);
        control_channel_append_str(new_name, channel_ctx->c_channel, 
                                   strlen(new_name));
        control_channel_send(channel_ctx->c_channel);

        if(!control_channel_read_expect(channel_ctx->c_channel, SUCCESS))
        {
            LOG(CLIENT_LOG, "Unknown CODE from server side," 
                "received CODE %d: \n",
                control_channel_get_ftp_type_in(channel_ctx->c_channel));
            operation_abort(channel_ctx->c_channel);
            return 0;
        }

        break;
    }

    case SERVER:
    {
        // Update design 
        // Read and seperate the arg into local_name and remote_name
        char* old_name = NULL;
        char* new_name = NULL;

        if(!control_channel_read_expect(channel_ctx->c_channel, RENAME))
        {
            LOG(SERVER_LOG, "Unknown CODE from client side," 
                "received CODE %d: \n",
                control_channel_get_ftp_type_in(channel_ctx->c_channel));
            operation_abort(channel_ctx->c_channel);
        }

        int data_len = control_channel_get_data_len_in(channel_ctx->c_channel) + 1;
        channel_ctx->source = (char*) malloc(data_len);
        memset(channel_ctx->source, 0, data_len);
        
        control_channel_get_str(channel_ctx->c_channel, channel_ctx->source, 
                                &channel_ctx->source_len);
        LOG(SERVER_LOG, "RUNNING\n");
        old_name = channel_ctx->source;
        new_name = strchr(channel_ctx->source, ' ');

        if(!new_name)
        {
            LOG(SERVER_LOG, "arguments lack remote_name, it contains only %s\n",
                channel_ctx->source);
            return 0;
        }

        *new_name = 0;
        new_name++;

        if(rename(old_name, new_name))
        {
            LOG(SERVER_LOG, "Fail to rename %s to %s \n", old_name, 
                new_name);
            control_channel_append_ftp_type(ABORT, channel_ctx->c_channel);
            control_channel_send(channel_ctx->c_channel);
            free(channel_ctx->source);
            return 0;
        }


        control_channel_append_ftp_type(SUCCESS, channel_ctx->c_channel);
        control_channel_send(channel_ctx->c_channel);
        free(channel_ctx->source);

        break;
    }
    
    default:
    {
        operation_abort(channel_ctx->c_channel);
        return -1;
    }

    }

    return 1;
}

int remove_local_dir(char* dir )
{
    char command[1024];
    memset(command, 0, 1024);
    snprintf(command, sizeof(command), "rm -rf \"%s\"", dir);
    return !system(command);
}

int remove_remote_dir(channel_context* channel_ctx)
{
    switch (channel_ctx->type)
    {
    case CLIENT:
    {
        control_channel_append_ftp_type(RMDIR, channel_ctx->c_channel);
        control_channel_append_str(channel_ctx->source, channel_ctx->c_channel, 
                                   channel_ctx->source_len);
        control_channel_send(channel_ctx->c_channel);

        if(!control_channel_read_expect(channel_ctx->c_channel, SUCCESS))
        {
            LOG(CLIENT_LOG, "Unknown CODE from client side," 
                "received CODE %d: \n",
                control_channel_get_ftp_type_in(channel_ctx->c_channel));
            operation_abort(channel_ctx->c_channel);
            return 0;
        }

        break;
    }
    
    case SERVER:
    {
        if(!control_channel_read_expect(channel_ctx->c_channel, RMDIR))
        {
            LOG(SERVER_LOG, "Unknown CODE from client side," 
                "received CODE %d: \n",
                control_channel_get_ftp_type_in(channel_ctx->c_channel));
            operation_abort(channel_ctx->c_channel);
            return 0;
        }
        
        int data_len = control_channel_get_data_len_in(channel_ctx->c_channel) + 1;
        channel_ctx->source = (char*) malloc(data_len);
        memset(channel_ctx->source, 0, data_len);

        control_channel_get_str(channel_ctx->c_channel, channel_ctx->source, 
                                &channel_ctx->source_len);
        memset(channel_ctx->source + data_len, 0, 
               sizeof(channel_ctx->source) - data_len);

        if(!remove_local_dir(channel_ctx->source))
        {
            LOG(SERVER_LOG, "Could not remove %s\n", channel_ctx->source);
            operation_abort(channel_ctx->c_channel);
            free(channel_ctx->source);
            return 0;
        }

        control_channel_append_ftp_type(SUCCESS, channel_ctx->c_channel);
        control_channel_send(channel_ctx->c_channel);
        free(channel_ctx->source);

        break;
    }

    default:
    {
        operation_abort(channel_ctx->c_channel);
        return 0;
    }

    }

    return 1;
}