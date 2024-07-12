#include "data.h"
#include "channel.h"
#include "file.h"
#include "cmd.h"
#include "ftp_type.h"
#include "packet.h"


int get(control_channel* c_channel, data_channel* d_channel)
{
    bool last_fragment = 0;
    char* file_name;
    int n_len;
    char* buf;
    int b_len;

    if(!control_channel_read_expect(c_channel, SEND) || 
       !control_channel_read_expect(c_channel, FTP_FILE_NAME))
    {
        control_channel_append_ftp_type(FTP_UNACK, c_channel);
        control_channel_send(c_channel);

        return 0;
    }

    control_channel_get_str(c_channel, file_name, &n_len);

    while(!last_fragment)
    {
        data_channel_read(d_channel);
        data_channel_get_str(d_channel, buf, &b_len);
        append_file(file_name, buf);
        last_fragment = d_channel->data_in->p_header->fragment_offset;
    }

    if(!control_channel_read_expect(c_channel, SUCCESS))
    {
        remove(file_name);
        LOG("Error when getting file\n");
        return 0;
    }

    return 1;
}

int send(control_channel* c_channel, data_channel* d_channel,
         char* file_name, int n_len)
{
    control_channel_append_ftp_type(SEND, c_channel);
    control_channel_send(c_channel);

    control_channel_append_ftp_type(FTP_FILE_NAME, c_channel);
    control_channel_append_str(file_name, c_channel, n_len);
    control_channel_send(c_channel);

    FILE* file = fopen(file_name, "rb");
    char buf[BUF_LEN];
    int byte;
    int ident = 0;

    if (file == NULL)
    {
        LOG("Error opening file\n");
        return 0;
    } 

    while(byte = read(file, buf, BUF_LEN) > 0)
    {
        data_channel_set_header(d_channel, ident, BUF_LEN, 
                                byte == BUF_LEN, SEND, 1);
        data_channel_append_str(buf, d_channel, byte);
        data_channel_send(d_channel);
    }

    if(byte < 0)
    {
        LOG("Error sending file\n");
        control_channel_append_ftp_type(ABORT, c_channel);
        control_channel_send(c_channel);

        return 0;
    }

    control_channel_append_ftp_type(SUCCESS, c_channel);
    control_channel_send(c_channel);
    
    return 1;
}