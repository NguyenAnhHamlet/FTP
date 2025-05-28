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
#include "algo/algo.h"
#include <signal.h>
#include "algo/stack.h"

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

int local_change_dir(channel_context* channel_ctx)
{
    return change_dir(channel_ctx->source);
}

int remote_change_dir(channel_context* channel_ctx)
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
        channel_ctx->source_len = data_len;
        memset(channel_ctx->source, 0, data_len);
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
        char* res = NULL;
        unsigned int ret_len = 0;

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
        
        if(!ll_dir(channel_ctx->source, &res, &ret_len))
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

// int idle_set_remote(channel_context* channel_ctx)
// {
//     switch (channel_ctx->type)
//     {
//     case CLIENT:
//     {
//         control_channel_append_ftp_type(IDLE, channel_ctx->c_channel);
//         control_channel_append_int( atoi(channel_ctx->source), channel_ctx->c_channel );
//         control_channel_send(channel_ctx->c_channel);
//         LOG(SERVER_LOG, "IDLE: %d %s\n", atoi(channel_ctx->source), channel_ctx->source);
//         if(!control_channel_read_expect(channel_ctx->c_channel, SUCCESS))
//         {
//             LOG(channel_ctx->log_type, "Set timeout remote failed\n");
//             LOG(channel_ctx->log_type, "Expected code %d but got %d",
//                 SUCCESS, control_channel_get_ftp_type_in(channel_ctx->c_channel));
//             operation_abort(channel_ctx->c_channel);

//             return 0;
//         }

//         break;
//     }
//     case SERVER:
//     {
//         if(!control_channel_read_expect(channel_ctx->c_channel, IDLE))
//         {
//             LOG(SERVER_LOG, "Unknown option\n");
//             operation_abort(channel_ctx->c_channel);

//             return 0;
//         }
        
//         unsigned int timeout = control_channel_get_int(channel_ctx->c_channel);

//         // TODO : update value timeout in file /etc/ftp/sftpd_config
//         const char tempconf[32] = "/etc/ftp/sftpd_config";
//         FILE* file = fopen(SFTPD_CONFIG, "r");
//         FILE *temp = fopen(tempconf, "w");
//         char line[256];
//         while (fgets(line, sizeof(line), file)) 
//         {
//             if (strstr(line, "IdleTimeOut")) 
//             {
//                 fprintf(temp, "%s %d\n", "IdleTimeOut", timeout);
//             }
//             else
//             {
//                 fputs(line, temp);
//             }
//         }

//         fclose(file);
//         fclose(temp);

//         if (remove(SFTPD_CONFIG) != 0) 
//         {
//             perror("Failed to delete the original file\n");
//             operation_abort(channel_ctx->c_channel);
//             return 0;
//         }

//         if (rename(tempconf, SFTPD_CONFIG) != 0) 
//         {
//             perror("Failed to rename config file\n");
//             operation_abort(channel_ctx->c_channel);    
//             return 0;
//         }

//         control_channel_append_ftp_type(SUCCESS, channel_ctx->c_channel);
//         control_channel_send(channel_ctx->c_channel);

//         break;
//     }

//     default:
//     {
//         operation_abort(channel_ctx->c_channel);
//         return -1;
//     }

//     }
// }

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
        memset(data, 0, data_len);
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

int list_local_dir(channel_context* channel_ctx)
{
    channel_ctx->ret = (char*) malloc(BUF_LEN);
    if(!list_dir(channel_ctx->source, channel_ctx->ret, 
                &channel_ctx->source_len))
    {
        strncpy(channel_ctx->ret, "Failed to read directory\n", BUF_LEN);
        return 0;
    }

    return 1;
}

int mdelte_remote_files(channel_context* channel_ctx)
{
    switch (channel_ctx->type)
    {
    case CLIENT:
    {
        // append files name 
        control_channel_append_ftp_type(MDELETE, channel_ctx->c_channel);
        control_channel_append_str(channel_ctx->source, channel_ctx->c_channel,
                                   channel_ctx->source_len);
        control_channel_send_wait(channel_ctx->c_channel);

        LOG(SERVER_LOG, "MDELETE 0 %s\n", channel_ctx->source);

        if(!control_channel_read_expect(channel_ctx->c_channel, SUCCESS))
        {
            char ret_file[BUF_LEN];
            unsigned int rlen;
            control_channel_get_str(channel_ctx->c_channel, ret_file, &rlen);
            LOG(channel_ctx->log_type, "Failed to mdelete file %s. "
                "Expected %d but received %d.", ret_file,
                SUCCESS, control_channel_get_ftp_type_in(channel_ctx->c_channel));
            return 0;
        }

        return 1;

        break;
    }
    
    case SERVER:
    {
        if(!control_channel_read_expect(channel_ctx->c_channel, MDELETE))
        {
            LOG(channel_ctx->log_type, "Unknown CODE from server side," 
                "received CODE %d: \n",
                control_channel_get_ftp_type_in(channel_ctx->c_channel));
            operation_abort(channel_ctx->c_channel);
            return 0;
        }

        LOG(SERVER_LOG, "MDELETE 1\n");

        unsigned int len = control_channel_get_data_len_in(channel_ctx->c_channel) + 1;
        channel_ctx->source = (char*) malloc(len);
        channel_ctx->source_len = len;
        memset(channel_ctx->source, 0, channel_ctx->source_len);
        control_channel_get_str(channel_ctx->c_channel, channel_ctx->source, 
                                &channel_ctx->source_len);
        
        LOG(SERVER_LOG, "MDELETE 2 %s\n", channel_ctx->source);

        char* ppos = channel_ctx->source;
        char* npos = NULL;
        while(npos = strchr(ppos, ' '))
        {
            *npos = 0;
            npos++;
            while(*npos == ' ') npos++;

            LOG(SERVER_LOG, "file name : %s\n", ppos);

            if(remove(ppos) != 0)
            {
                LOG(channel_ctx->log_type, "Failed to delete file %s", ppos);
                control_channel_append_ftp_type(ABORT, channel_ctx->c_channel);
                control_channel_append_str(ppos, channel_ctx->c_channel, strlen(ppos));
                control_channel_send(channel_ctx->c_channel);
                return 0;
            }

            ppos = npos;
        }

        LOG(SERVER_LOG, "file name : %s\n", ppos);

        if(remove(ppos) != 0)
        {
            LOG(channel_ctx->log_type, "Failed to delete file %s", ppos);
            control_channel_append_ftp_type(ABORT, channel_ctx->c_channel);
            control_channel_append_str(ppos, channel_ctx->c_channel, strlen(ppos));
            control_channel_send(channel_ctx->c_channel);
            return 0;
        }

        LOG(SERVER_LOG, "MDELETE 3\n");

        control_channel_append_ftp_type(SUCCESS, channel_ctx->c_channel);
        control_channel_send(channel_ctx->c_channel);

        break;
    }

    default:
    {
        operation_abort(channel_ctx->c_channel);
        return -1;
    }
    
    }
}

int remote_mmkdir(channel_context* channel_ctx)
{
    switch (channel_ctx->type)
    {
    case CLIENT:
    {
        // append multiple dir name
        control_channel_append_ftp_type(MMKDIR, channel_ctx->c_channel);
        control_channel_append_str(channel_ctx->source, channel_ctx->c_channel,
                                   channel_ctx->source_len);
        control_channel_send(channel_ctx->c_channel);

        if(!control_channel_read_expect(channel_ctx->c_channel, SUCCESS))
        {
            LOG(channel_ctx->log_type, "Unknown CODE from server side," 
                "received CODE %d: \n",
                control_channel_get_ftp_type_in(channel_ctx->c_channel));
            operation_abort(channel_ctx->c_channel);
            return 0;
        }

        break;
    }
        

    case SERVER:
    {
        if(!control_channel_read_expect(channel_ctx->c_channel, MMKDIR))
        {
            LOG(channel_ctx->log_type, "Unknown CODE from server side," 
                "received CODE %d: \n",
                control_channel_get_ftp_type_in(channel_ctx->c_channel));
            operation_abort(channel_ctx->c_channel);
            return 0;
        }

        char* dirname = NULL;
        char* uppos = NULL;
        char dirsname[BUF_LEN];
        unsigned int rlen;
        control_channel_get_str(channel_ctx->c_channel, dirsname, &rlen);
        dirname = dirsname;

        while((uppos = strchr(dirname, ' ')))
        {
            *uppos = 0;
            uppos++;
            while(*uppos == ' ') uppos++;

            if(mkdir(dirname, 0755) != 0)
            {
                LOG(channel_ctx->log_type, "Unknown CODE from server side," 
                    "received CODE %d: \n",
                    control_channel_get_ftp_type_in(channel_ctx->c_channel));
                operation_abort(channel_ctx->c_channel);
                control_channel_append_ftp_type(ABORT, channel_ctx->c_channel);
                control_channel_send(channel_ctx->c_channel);
                return 0;
            }

            dirname = uppos;
        }

        // last one in str
        if(mkdir(dirname, 0755) != 0)
        {
            LOG(channel_ctx->log_type, "Unknown CODE from server side," 
                "received CODE %d: \n",
                control_channel_get_ftp_type_in(channel_ctx->c_channel));
            operation_abort(channel_ctx->c_channel);
            control_channel_append_ftp_type(ABORT, channel_ctx->c_channel);
            control_channel_send(channel_ctx->c_channel);
            return 0;
        }

        control_channel_append_ftp_type(SUCCESS, channel_ctx->c_channel);
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

int remote_mkdir(channel_context* channel_ctx)
{
    switch (channel_ctx->type)
    {
    case CLIENT:
    {
        // append dir name
        control_channel_append_ftp_type(MKDIR, channel_ctx->c_channel);
        control_channel_append_str(channel_ctx->source, channel_ctx->c_channel,
                                   channel_ctx->source_len);
        control_channel_send(channel_ctx->c_channel);

        if(!control_channel_read_expect(channel_ctx->c_channel, SUCCESS))
        {
            LOG(channel_ctx->log_type, "Unknown CODE from server side," 
                "received CODE %d: \n",
                control_channel_get_ftp_type_in(channel_ctx->c_channel));
            operation_abort(channel_ctx->c_channel);
            return 0;
        }

        break;
    }
        

    case SERVER:
    {
        if(!control_channel_read_expect(channel_ctx->c_channel, MKDIR))
        {
            LOG(channel_ctx->log_type, "Unknown CODE from server side," 
                "received CODE %d: \n",
                control_channel_get_ftp_type_in(channel_ctx->c_channel));
            operation_abort(channel_ctx->c_channel);
            return 0;
        }

        char dirname[BUF_LEN];
        unsigned int rlen;
        control_channel_get_str(channel_ctx->c_channel, dirname, &rlen);
        if(mkdir(dirname, 0755) != 0)
        {
            LOG(channel_ctx->log_type, "Unknown CODE from server side," 
                "received CODE %d: \n",
                control_channel_get_ftp_type_in(channel_ctx->c_channel));
            operation_abort(channel_ctx->c_channel);
            control_channel_append_ftp_type(ABORT, channel_ctx->c_channel);
            control_channel_send(channel_ctx->c_channel);
            return 0;
        }

        control_channel_append_ftp_type(SUCCESS, channel_ctx->c_channel);
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

int mlist_remote_dir(channel_context* channel_ctx)
{
    switch (channel_ctx->type)
    {
    case CLIENT:
    {
        control_channel_append_ftp_type(MLS, channel_ctx->c_channel);
        control_channel_append_str(channel_ctx->source, channel_ctx->c_channel, 
                                   channel_ctx->source_len);
        control_channel_send(channel_ctx->c_channel);

        if(!control_channel_read_expect(channel_ctx->c_channel, MLS))
        {
            LOG(CLIENT_LOG, "Failed to mlist dir, received CODE: %d\n", 
                control_channel_get_ftp_type_in(channel_ctx->c_channel));
            operation_abort(channel_ctx->c_channel);

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
        char res[BUF_LEN];
        unsigned int ret_len;
        char* indiv_dir = NULL, *npos = NULL;

        memset(res, 0, BUF_LEN);

        if(!control_channel_read_expect(channel_ctx->c_channel, MLS))
        {
            LOG(SERVER_LOG, "Failed to mlist dir, received CODE: %d\n", 
                control_channel_get_ftp_type_in(channel_ctx->c_channel));
            operation_abort(channel_ctx->c_channel);

            return 0;
        }

        int data_len = control_channel_get_data_len_in(channel_ctx->c_channel) + 1;
        channel_ctx->source = (char*) malloc(data_len);
        memset(channel_ctx->source, 0, data_len);

        control_channel_get_str(channel_ctx->c_channel, channel_ctx->source, 
                                &channel_ctx->source_len);                       
        
        control_channel_append_ftp_type(MLS, channel_ctx->c_channel);

        indiv_dir = channel_ctx->source;
        while(npos = strchr(indiv_dir, ' '))
        {
            *npos = 0;
            npos++;
            while(*npos == ' ') npos++;
            
            memset(res, 0, sizeof(res));
            if(!list_dir(indiv_dir, res, &ret_len))
            {
                LOG(SERVER_LOG, "List dir %s failed\n", channel_ctx->source);
                operation_abort(channel_ctx->c_channel);
                return 0;
            }
            
            control_channel_append_str(indiv_dir, channel_ctx->c_channel, strlen(indiv_dir));
            control_channel_append_str(":\n", channel_ctx->c_channel, 2);
            control_channel_append_str(res, channel_ctx->c_channel, strlen(res));
            control_channel_append_str("\n", channel_ctx->c_channel, 1);

            indiv_dir = npos;
        }
        
        memset(res, 0, sizeof(res));
        if(!list_dir(indiv_dir, res, &ret_len))
        {
            LOG(SERVER_LOG, "List dir %s failed\n", channel_ctx->source);
            operation_abort(channel_ctx->c_channel);
            return 0;
        }
        LOG(SERVER_LOG, "DIR: %s\n", indiv_dir);
        LOG(SERVER_LOG, "VALUE: %s\n", res);

        control_channel_append_str(indiv_dir, channel_ctx->c_channel, strlen(indiv_dir));
        control_channel_append_str(":\n", channel_ctx->c_channel, 2);
        control_channel_append_str(res, channel_ctx->c_channel, strlen(res));
        control_channel_append_str("\n", channel_ctx->c_channel, 1);

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

int local_prompt(channel_context* channel_ctx)
{
    channel_ctx->prompt = str_to_int(channel_ctx->source, channel_ctx->source_len); 
}

int local_pwd(channel_context* channel_ctx)
{
    char cwd[BUF_LEN];
    memset(cwd, 0, sizeof(cwd));
    if(!getcwd(cwd, sizeof(cwd)))
    {
        LOG(channel_ctx->log_type, "Failed to list local dir\n");
        return 0;
    }

    channel_ctx->ret = (char*) malloc(strlen(cwd));
    strncpy(channel_ctx->ret, cwd, strlen(cwd));
    return 1;
}

int remote_pwd(channel_context* channel_ctx)
{
    switch (channel_ctx->type)
    {
    case CLIENT:
    {
        control_channel_append_ftp_type(PWD, channel_ctx->c_channel);
        control_channel_append_str(channel_ctx->source, channel_ctx->c_channel, 
                                   channel_ctx->source_len);
        control_channel_send(channel_ctx->c_channel);

        if(!control_channel_read_expect(channel_ctx->c_channel, PWD))
        {
            LOG(CLIENT_LOG, "Unknown CODE from server side," 
                "received CODE %d: \n",
                control_channel_get_ftp_type_in(channel_ctx->c_channel));
            operation_abort(channel_ctx->c_channel);
            return 0;
        }

        unsigned int len = control_channel_get_data_len_in(channel_ctx->c_channel) + 1 ;
        channel_ctx->ret = (char*) malloc(len);
        channel_ctx->ret_len = len;
        if(!channel_ctx->ret)
        {
            LOG(CLIENT_LOG, "Unknown CODE from server side," 
                "received CODE %d: \n",
                control_channel_get_ftp_type_in(channel_ctx->c_channel));
            operation_abort(channel_ctx->c_channel);
            return 0;
        }

        control_channel_get_str(channel_ctx->c_channel, channel_ctx->ret, 
                                &channel_ctx->ret_len);
        
        control_channel_append_ftp_type(SUCCESS, channel_ctx->c_channel);
        control_channel_send(channel_ctx->c_channel);

        break;
    }
    
    case SERVER:
    {
        if(!control_channel_read_expect(channel_ctx->c_channel, PWD))
        {
            LOG(channel_ctx->log_type, "Unknown CODE from server side," 
                "received CODE %d: \n",
                control_channel_get_ftp_type_in(channel_ctx->c_channel));
            operation_abort(channel_ctx->c_channel);
            return 0;
        }

        char* data = NULL;
        char cwd[BUF_LEN];
        int len = control_channel_get_data_len_in(channel_ctx->c_channel) + 1;
        data = (char*) malloc(len);

        if(!data)
        {
            LOG(channel_ctx->log_type, "Unknown CODE from server side," 
                "received CODE %d: \n",
                control_channel_get_ftp_type_in(channel_ctx->c_channel));
            operation_abort(channel_ctx->c_channel);
            return 0;
        }

        control_channel_get_str(channel_ctx->c_channel, data, &len);

        memset(cwd, 0, sizeof(cwd));
        if(!getcwd(cwd, sizeof(cwd)))
        {
            LOG(channel_ctx->log_type, "Unknown CODE from server side," 
                "received CODE %d: \n",
                control_channel_get_ftp_type_in(channel_ctx->c_channel));
            operation_abort(channel_ctx->c_channel);
            return 0;
        }

        control_channel_append_ftp_type(PWD, channel_ctx->c_channel);
        control_channel_append_str(cwd, channel_ctx->c_channel, strlen(cwd));
        control_channel_send_wait(channel_ctx->c_channel);

        if(!control_channel_read_expect(channel_ctx->c_channel, SUCCESS))
        {
            LOG(channel_ctx->log_type, "Unknown CODE from server side," 
                "received CODE %d: \n",
                control_channel_get_ftp_type_in(channel_ctx->c_channel));
            operation_abort(channel_ctx->c_channel);
            return 0;
        }

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

// int status(channel_context* channel_ctx)
// {
//     char buf[BUF_LEN];
//     char* hostnamebuf;
    
//     hostnamebuf = (char*) malloc(16);
//     memset(buf, 0, BUF_LEN);
//     memset(hostnamebuf, 0, 16);

//     hostname(control_channel_get_sockfd_in(channel_ctx->c_channel), &hostnamebuf);
//     sprintf(buf, "Connected to %s\n", hostnamebuf);
//     buffer_append_str(channel_ctx->retb, buf, strlen(buf));

//     // TODO: append user's name here
//     // Session time : 
//     // Server uptime : 
//     // <> users currently logged in 
//     // Available command : 
    
//     for(int i =0; i< MAXPROCCESS+ 1; i++ )
//     {
//         if(channel_ctx->usedpipe[i] > 0)
//         {
//             if((kill(channel_ctx->usedpipe[i], 0) == 0))
//             {
//                 channel_ctx->usedpipe[i] = 0;
//                 close(channel_ctx->pipe_fd[i][0]);
//                 close(channel_ctx->pipe_fd[i][1]);
//                 push(&channel_ctx->free_pipe, i);
//             }
//             else 
//             {
//                 kill(channel_ctx->usedpipe[i], SIGUSR1);
//                 read(channel_ctx->pipe_fd[i][0], buf, BUF_LEN);
//                 buffer_append_str(channel_ctx->retb, buf, strlen(buf));
//                 buffer_append_str(channel_ctx->retb, "\n", 1);
//                 memset(buf, 0, BUF_LEN);
//             }
//         }
//     }

//     return 1;
// }

int remote_system_info(channel_context* channel_ctx)
{
    switch (channel_ctx->type)
    {
    case CLIENT:
    {
        control_channel_append_ftp_type(SYSTEM, channel_ctx->c_channel);
        control_channel_send(channel_ctx->c_channel);

        if(!control_channel_read_expect(channel_ctx->c_channel, SYSTEM))
        {
            LOG(channel_ctx->log_type, "Expected %d but got %d instead\n",
                                        SYSTEM, control_channel_get_ftp_type_in(channel_ctx->c_channel));
            operation_abort(channel_ctx->c_channel);
            return 0;
        }

        unsigned int len = control_channel_get_data_len_in(channel_ctx->c_channel) + 1;
        channel_ctx->ret_len = len;
        channel_ctx->ret = (char*) malloc(len);
        if(!channel_ctx->ret)
        {
            LOG(channel_ctx->log_type, "Failed to allocate memory\n");
            operation_abort(channel_ctx->c_channel);
            return 0;
        }

        control_channel_get_str(channel_ctx->c_channel, channel_ctx->ret, &channel_ctx->ret_len);
        
        control_channel_append_ftp_type(SUCCESS, channel_ctx->c_channel);
        control_channel_send(channel_ctx->c_channel);

        break;
    }
    
    case SERVER:
    {
        if(!control_channel_read_expect(channel_ctx->c_channel, SYSTEM))
        {
            LOG(channel_ctx->log_type, "Expected %d but got %d instead\n", 
                SYSTEM, control_channel_get_ftp_type_in(channel_ctx->c_channel));
            operation_abort(channel_ctx->c_channel);
            return 0;
        }
        
        char* ret = NULL;
        FILE* file = NULL;
        unsigned int bytes = 0;
        char  buf[BUF_LEN];
        
        memset(buf, 0, sizeof(buf));
        if(!read_file(OS_RELEASE, &file))
        {
            LOG(channel_ctx->log_type, "Fail to create file %s\n", OS_RELEASE);
            operation_abort(channel_ctx->c_channel);
            return 0;
        }

        if(!file)
        {
            LOG(channel_ctx->log_type, "Failed to open file %s", OS_RELEASE);
            operation_abort(channel_ctx->c_channel);
            return 0;
        }

        bytes = fread(buf, sizeof(char), BUF_LEN, file);

        if(bytes == 0)
        {
            LOG(channel_ctx->log_type, "Failed to open file %s", OS_RELEASE);
            operation_abort(channel_ctx->c_channel);
            fclose(file);
            return 0;
        }

        control_channel_append_ftp_type(SYSTEM, channel_ctx->c_channel);
        control_channel_append_str(buf, channel_ctx->c_channel, strlen(buf));
        control_channel_send(channel_ctx->c_channel);

        if(!control_channel_read_expect(channel_ctx->c_channel, SUCCESS))
        {
            LOG(channel_ctx->log_type, "Expected %d but got %d instead\n", 
                SUCCESS, control_channel_get_ftp_type_in(channel_ctx->c_channel));
            operation_abort(channel_ctx->c_channel);
            return 0;
        }

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

int passmode(channel_context* channel_ctx)
{   
    channel_ctx->passmode = ~ channel_ctx->passmode;
}
