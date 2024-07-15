#include "common/control.h"
#include "common/common.h"
#include "ftp_type.h"
#include "cmd.h"
#include "common/channel.h"
#include "log/ftplog.h"
#include "common/file.h"

int remote_file_exist(control_channel* c_channel, endpoint_type type,
                      char* file_name, unsigned int n_len)
{
    switch (type)
    {
    case CLIENT:
    {
        control_channel_append_ftp_type(ASK_FILE_EXIST, c_channel);
        control_channel_send(c_channel);
        if(!control_channel_read_expect(c_channel, FILE_EXIST))
        {
            LOG("File %s does not exist\n", file_name);
            return 0;
        }

        LOG("File %s exist, start appending file to remote\n", file_name);

        break;
    }
    
    case SERVER:
    {
        char* file_name;
        int n_len;

        if(!control_channel_read_expect(c_channel, ASK_FILE_EXIST))
        {
            LOG("Not expected this code number %d\n", 
                c_channel->data_in->p_header->packet_type);
            
            return 0;
        }

        LOG("Receive code number %d\n Start checking file existence\n",
            c_channel->data_in->p_header->packet_type);

        control_channel_get_str(c_channel, file_name, n_len);

        if(not_exist(file_name))
            control_channel_append_int(FILE_NOT_EXIST, c_channel);
        else 
            control_channel_append_int(FILE_EXIST, c_channel);

        control_channel_send(c_channel);

        break;
    }

    default:
    {
        LOG("Unknown type %d\n", type);
        return -1;
        break;
    }
    }

    return 1;
}