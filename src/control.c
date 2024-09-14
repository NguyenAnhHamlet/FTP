#include "control.h"
#include "common/common.h"
#include "common/ftp_type.h"
#include "common/cmd.h"
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

int remote_file_exist(control_channel* c_channel, endpoint_type type,
                      char* file_name, unsigned int n_len)
{
    switch (type)
    {
    case CLIENT:
    {
        control_channel_set_header(c_channel, 
                                   0, sizeof(Packet),
                                   0, ASK_FILE_EXIST, 0);
        control_channel_send(c_channel);
        if(!control_channel_read_expect(c_channel, FILE_EXIST))
        {
            LOG(CLIENT_LOG, "File %s does not exist\n", file_name);
            operation_abort(c_channel);
            return 0;
        }

        LOG(CLIENT_LOG, "File %s exist, start appending file to remote\n", file_name);

        break;
    }
    
    case SERVER:
    {
        char* file_name;
        int n_len;

        if(!control_channel_read_expect(c_channel, ASK_FILE_EXIST))
        {
            LOG(SERVER_LOG, "Not expected this code number %d\n", 
                c_channel->data_in->p_header->packet_type);
            
            return 0;
        }

        LOG(SERVER_LOG, 
            "Receive code number %d\n Start checking file existence\n",
            c_channel->data_in->p_header->packet_type);

        control_channel_get_str(c_channel, file_name, &n_len);

        if(not_exist(file_name))
            control_channel_append_int(FILE_NOT_EXIST, c_channel);
        else 
            control_channel_append_int(FILE_EXIST, c_channel);

        control_channel_send(c_channel);

        break;
    }

    default:
    {
        operation_abort(c_channel);
        return -1;
    }

    }

    return 1;
}

int change_dir(control_channel* c_channel, char* dir, int d_len,
               endpoint_type type)
{
    int res =1;
    switch (type)
    {
    case CLIENT:
    {
        control_channel_set_header(c_channel, 
                                   0, sizeof(Packet),
                                   0, CD, 0);
        control_channel_append_str(dir, c_channel, d_len);

        if(!control_channel_send(c_channel) || 
        !control_channel_read_expect(c_channel, SUCCESS))
        {
            LOG(CLIENT_LOG, "Fail to change dir\n");
            operation_abort(c_channel);
            return 0;
        }

        LOG(CLIENT_LOG, "Successfully changed dir\n");

        break;
    }
    case SERVER:
    {
        char* dir;
        int d_len;
        if(!control_channel_read_expect(c_channel, CD))
        {
            LOG(SERVER_LOG, "Unknown option\n");
            operation_abort(c_channel);
            return 0;
        }

        control_channel_get_str(c_channel, dir, &d_len);
        if(chdir(dir))
        {
            LOG(SERVER_LOG, "Change dir failed\n");
            operation_abort(c_channel);
            return 0;
        }

        LOG(SERVER_LOG, "Change dir done\n");
        control_channel_append_ftp_type(SUCCESS, c_channel);
        control_channel_send(c_channel);

        break;
    }
    
    default:
    {
        operation_abort(c_channel);
        return -1;
    }

    }

    return res;
}

int change_mode(control_channel* c_channel, char* chmod_cmd, int cmd_len,
                endpoint_type type)
{
    switch (type)
    {
    case CLIENT:
    {
        control_channel_set_header(c_channel, 
                                   0, sizeof(Packet),
                                   0, CHMOD, 0);
        control_channel_append_str(chmod_cmd, c_channel, cmd_len);


        if(!control_channel_send(c_channel) ||
           !control_channel_read_expect(c_channel, SUCCESS))
        {
            LOG(CLIENT_LOG, "Failed to change mode\n");
            operation_abort(c_channel);

            return 0;
        }

        LOG(CLIENT_LOG, "Done change mode\n");

        break;
    }
    case SERVER:
    {
        char* file_name;
        char* mode;
        char* token;
        int no;

        if(!control_channel_read_expect(c_channel, CHMOD))
        {
            LOG(SERVER_LOG, "Unknown option\n");
            operation_abort(c_channel);

            return 0;
        }

        control_channel_get_str(c_channel, chmod_cmd, &cmd_len);
        while(token = strtok(chmod_cmd, " "))
        {
            switch (no)
            {
            case 0:
                file_name = chmod_cmd + (token - chmod_cmd) + 1;
                break;
            case 1:
                mode = chmod_cmd + (token - chmod_cmd) + 1;
            default:
                return 0;
                break;
            }
            token = '\0';
            token++;
            chmod_cmd = token;
        }

        if(chmod(file_name, strtol(mode, 0, 8)))
        {
            LOG(SERVER_LOG, "Fail to change mode\n");
            operation_abort(c_channel);

            return 0;
        }

        LOG(SERVER_LOG, "Change mode file done\n");
        control_channel_append_ftp_type(SUCCESS, c_channel);
        control_channel_send(c_channel);

        break;
    }

    default:
    {
        operation_abort(c_channel);
        return -1;
    }

    }

    return 1;
}

int delete_remote_file(control_channel* c_channel, char* file_name, 
                unsigned int n_len, endpoint_type type)
{
    switch (type)
    {
    case CLIENT:
    {
        control_channel_set_header(c_channel, 
                                   0, sizeof(Packet),
                                   0, DELETE, 0);
        control_channel_append_str(file_name, c_channel, n_len);

        if(!control_channel_send(c_channel) ||
           !control_channel_read_expect(c_channel, SUCCESS))
        {
            LOG(CLIENT_LOG, "Delete remote file failed\n");
            operation_abort(c_channel);

            return 0;
        }

        LOG(CLIENT_LOG, "Delete remote file done\n");
        break;
    }
    case SERVER:
    {
        if(!control_channel_read_expect(c_channel, DELETE))
        {
            LOG(SERVER_LOG, "Unknown option\n");
            operation_abort(c_channel);

            return 0;
        }

        control_channel_get_str(c_channel, file_name, &n_len);
        if(remove(file_name))
        {
            LOG(SERVER_LOG, "Delete file %s failed\n", file_name);
            operation_abort(c_channel);

            return 0;
        }

        LOG(SERVER_LOG, "Delete file %s done\n", file_name);
        control_channel_append_ftp_type(SUCCESS, c_channel);
        control_channel_send(c_channel);
        break;
    }
    
    default:
    {
        operation_abort(c_channel);
        return -1;
    }

    }

    return 1;
}

int list_remote_dir(control_channel* c_channel, char* dir, int cmd_len,
                    char* res, unsigned int* r_len, endpoint_type type)
{
    switch (type)
    {
    case CLIENT:
    {
        control_channel_set_header(c_channel, 0, sizeof(Packet),
                                   0, _DIR, 0);
        control_channel_append_str(dir, c_channel, cmd_len);

        if(!control_channel_send(c_channel) ||
           !control_channel_read_expect(c_channel, _DIR))
        {
            LOG(CLIENT_LOG, "Failed to list dir\n");
            operation_abort(c_channel);

            return 0;
        }

        control_channel_get_str(c_channel, res, r_len);
        control_channel_append_ftp_type(FTP_ACK, c_channel);
        control_channel_send(c_channel);

        break;
    }
    case SERVER:
    {
        char* res = (char*) malloc(BUF_LEN);
        int r_len;
        if(!control_channel_read_expect(c_channel, _DIR))
        {
            LOG(SERVER_LOG, "Unknown option\n");
            operation_abort(c_channel);

            return 0;
        }

        control_channel_get_str(c_channel, dir, &cmd_len);                       
        if(!list_dir(dir, res, &r_len))
        {
            LOG(SERVER_LOG, "List dir failed\n");
            operation_abort(c_channel);

            return 0;
        }

        control_channel_set_header(c_channel, 0, sizeof(Packet),
                                   0, _DIR, 0);
        control_channel_append_str(res, c_channel, r_len);
        
        if(!control_channel_send(c_channel) ||
           !control_channel_read_expect(c_channel, FTP_ACK))
        {
            LOG(SERVER_LOG, "Send result failed\n");
            operation_abort(c_channel);

            return 0;
        }

        break;
    }
    
    default:
    {
        operation_abort(c_channel);
        return -1;
    }

    }

    return 1;
}

int list_current_dir(control_channel* c_channel, char* res, 
                     unsigned int* r_len, endpoint_type type)
{
    return list_remote_dir(c_channel, ".", 1, res, r_len, type);
}

int idle_set_remote(control_channel* c_channel, unsigned int* time_out, 
                    endpoint_type type)
{
    switch (type)
    {
    case CLIENT:
    {
        control_channel_set_header(c_channel, 0, sizeof(Packet), 
                                   0, IDLE, 0);
        control_channel_append_int( (int) *time_out, c_channel );
        if(!control_channel_send(c_channel) || 
           !control_channel_read_expect(c_channel, SUCCESS))
        {
            LOG(CLIENT_LOG, "Set timeout remote failed\n");
            operation_abort(c_channel);

            return 0;
        }

        break;
    }
    case SERVER:
    {
        if(!control_channel_read_expect(c_channel, IDLE))
        {
            LOG(SERVER_LOG, "Unknown option\n");
            operation_abort(c_channel);

            return 0;
        }

        *time_out = control_channel_get_int(c_channel);

        break;
    }

    default:
    {
        operation_abort(c_channel);
        return -1;
    }

    }
}

int remote_modtime(control_channel* c_channel, endpoint_type type,  
                   char* file_name, unsigned int* n_len, char* modetime, 
                   unsigned int* m_len)
{
    switch (type)
    {
    case CLIENT :
    {
        control_channel_set_header(c_channel, 0, sizeof(Packet), 0, MODTIME, 0);
        control_channel_append_str(file_name, c_channel, *n_len);
        
        if(!control_channel_send(c_channel) ||
           !control_channel_read_expect(c_channel, MODTIME))
        {
            LOG(CLIENT_LOG, "Could not get mod time of remote file\n");
            operation_abort(c_channel);

            return 0;
        }

        control_channel_get_str(c_channel, modetime, m_len);

        break;
    }
    
    case SERVER:
    {
        struct stat attrib;

        if(!control_channel_read_expect(c_channel, MODTIME))
        {
            LOG(SERVER_LOG, "Unknown option\n");
            operation_abort(c_channel);

            return 0;
        }

        control_channel_get_str(c_channel, file_name, n_len);

        stat(file_name, &attrib);
        strftime(modetime, 50, "%Y-%m-%d %H:%M:%S", localtime(&attrib.st_mtime));

        control_channel_set_header(c_channel, 0, sizeof(Packet), 0, MODTIME, 0);
        control_channel_append_str(modetime, c_channel, strlen(modetime));

        if(!control_channel_send(c_channel))
        {
            LOG(SERVER_LOG, "Send modtime failed\n");
            operation_abort(c_channel);
            
            return 0;
        }

        break;
    }

    default:
    {
        operation_abort(c_channel);
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

int remote_get_size(control_channel* c_channel, char* file_name, int n_len, 
                    unsigned int* file_size, endpoint_type type)
{
    switch (type)
    {
    case CLIENT :
    {
        control_channel_set_header(c_channel, 0, sizeof(Packet), 0, SIZE, 0);
        control_channel_append_str(file_name, c_channel, n_len);
        
        if(!control_channel_send(c_channel) ||
           !control_channel_read_expect(c_channel, SIZE))
        {
            LOG(CLIENT_LOG, "Could not get mod time of remote file\n");
            operation_abort(c_channel);

            return 0;
        }

        *file_size = control_channel_get_int(c_channel);

        break;
    }
    
    case SERVER:
    {
        struct stat attrib;

        if(!control_channel_read_expect(c_channel, SIZE))
        {
            LOG(SERVER_LOG, "Unknown option\n");
            operation_abort(c_channel);

            return 0;
        }

        control_channel_get_str(c_channel, file_name, &n_len);

        stat(file_name, &attrib);

        control_channel_set_header(c_channel, 0, sizeof(Packet), 0, SIZE, 0);
        control_channel_append_int(attrib.st_size, c_channel);

        if(!control_channel_send(c_channel))
        {
            LOG(SERVER_LOG, "Send modtime failed\n");
            operation_abort(c_channel);
            
            return 0;
        }

        break;
    }

    default:
    {
        operation_abort(c_channel);
        return -1;
    }

    }

    return 1;
}

int remote_change_name(control_channel* c_channel, char* file_name, int n_len,
                       char* update_name, int u_len, endpoint_type type)
{
    switch (type)
    {
    case CLIENT:
    {
        control_channel_set_header(c_channel, 0, sizeof(Packet), 0, RENAME, 0);
        control_channel_append_str(file_name, c_channel, n_len);
        control_channel_append_str(" ", c_channel, 1);
        control_channel_append_str(update_name, c_channel, u_len);

        if(!control_channel_send(c_channel) || 
           !control_channel_read_expect(c_channel, SUCCESS))
        {
            LOG(CLIENT_LOG, "Fail operation change remote server file name\n");
            return 0;
        }

        break;
    }

    case SERVER:
    {
        if(!control_channel_read_expect(c_channel, RENAME))
            operation_abort(c_channel);
        
        control_channel_get_str(c_channel, file_name, &n_len);
        while (*update_name != ' ') 
            update_name++;
        update_name = '\0';
        update_name++;

        rename(file_name, update_name);

        control_channel_append_ftp_type(SUCCESS, c_channel);
        if(!control_channel_send(c_channel))
        {
            operation_abort(c_channel);
            return 0;
        }

        break;
    }
    
    default:
    {
        operation_abort(c_channel);
        return -1;
    }

    }

    return 1;
}

int unlink_cb(const char *fpath, const struct stat *sb, int typeflag)
{
    int rv = remove(fpath);

    if (rv)
        perror(fpath);

    return rv;
}

int remove_local_dir(char* dir )
{
    return ftw(dir, unlink_cb, FTW_NS);
}

int remove_remote_dir(control_channel* c_channel, char* dir, 
                      int d_len, endpoint_type type )
{
    switch (type)
    {
    case CLIENT:
    {
        control_channel_set_header(c_channel, 0, sizeof(Packet), 0, RMDIR, 0);
        control_channel_append_str(dir, c_channel, d_len);

        if(!control_channel_send(c_channel) || 
           !control_channel_read_expect(c_channel, SUCCESS))
        {
            LOG(CLIENT_LOG, "Fail to remove remote dir\n");
            return 0;
        }


        break;
    }
    
    case SERVER:
    {
        if(!control_channel_read_expect(c_channel, RMDIR))
        {
            operation_abort(c_channel);
            return 0;
        }
        
        control_channel_get_str(c_channel, dir, &d_len);

        if(!remove_local_dir(dir))
        {
            operation_abort(c_channel);
            return 0;
        }

        break;
    }

    default:
    {
        operation_abort(c_channel);
        return -1;
    }

    }

    return 1;
}
