#include "data.h"
#include "common/channel.h"
#include "common/file.h"
#include "common/cmd.h"
#include "common/ftp_type.h"
#include "common/packet.h"
#include "control.h"
#include <time.h>
#include "algo/algo.h"
#include "common/file.h"
#include "log/ftplog.h"

int data_conn(control_channel* c_channel, data_channel* d_channel,
              socket_ftp* c_socket, socket_ftp* d_socket, 
              endpoint_type type )
{
    switch (type)
    {
    case CLIENT:
    {
        control_channel_append_ftp_type(GET, c_channel);
        control_channel_send(c_channel);

        if(control_channel_read_expect(c_channel, FTP_ACK) <= 0 )
        {
            LOG(CLIENT_LOG, "Fail to establish the data connection\n");
            operation_abort(c_channel);
            return 0;
        }

        d_socket = create_ftp_socket(c_socket->ip_addr, 
                                     c_socket->endpoint_addr->sin_family, 
                                     CLIENT, PORT_DATA, DATA, cre_socket());
                                     
        data_channel_init_socket_ftp(d_channel, d_socket, d_socket, CLIENT, NULL);
        data_channel_set_time_out(d_channel, DEFAULT_CHANNEL_TMOUT);

        break;
    }

    case SERVER:
    {
        d_socket = create_ftp_socket(NULL, AF_INET, SERVER, PORT_DATA, DATA, cre_socket());
        data_channel_init_socket_ftp(d_channel, d_socket, d_socket, SERVER, NULL);
        data_channel_set_time_out(d_channel, DEFAULT_CHANNEL_TMOUT);

        control_channel_append_ftp_type(FTP_ACK, c_channel);
        control_channel_send(c_channel);

        if(!control_channel_read_expect(c_channel, FTP_ACK))
        { 
            LOG(CLIENT_LOG, "Failed to receive ACK from client\n");
            operation_abort(c_channel);
            return 0;
        }
    }
    
    default:
    {
        operation_abort(c_channel);
        break;
    }

    }

    return 1;
}

int get(control_channel* c_channel, data_channel* d_channel,
        char* file_name, int* n_len, endpoint_type type)
{
    bool last_fragment = 0;
    char* buf;
    int b_len;

    switch (type)
    {
    case CLIENT:
    {
        control_channel_set_header(c_channel, 0, sizeof(Packet), 0, GET, 0);
        control_channel_append_str(file_name, c_channel, *n_len);

        if(!control_channel_send(c_channel) || 
        !control_channel_read_expect(c_channel, FILE_EXIST))
        {
            LOG(CLIENT_LOG, "GET operation failed\n");
            operation_abort(c_channel);
            
            return 0;
        }

        break;
    }

    case SERVER:
    {
        if(!control_channel_read_expect(c_channel, PUT) || 
           !control_channel_read_expect(c_channel, FTP_FILE_NAME))
        {
            operation_abort(c_channel);

            return 0;
        }

        control_channel_get_str(c_channel, file_name, n_len);
        
        break;
    }
    
    default:
    {
        operation_abort(c_channel);
        return -1;
    }

    }

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
        LOG(SERVER_LOG, "Error when getting file\n");
        operation_abort(c_channel);
        return 0;
    }

    return 1;
}

int put(control_channel* c_channel, data_channel* d_channel,
         char* file_name, int n_len, endpoint_type type)
{
    FILE* file;
    char buf[BUF_LEN];
    int byte;
    int ident = -1;   

    switch (type)
    {
    case CLIENT:
    {
        control_channel_append_ftp_type(PUT, c_channel);
        control_channel_send(c_channel);

        control_channel_append_ftp_type(FTP_FILE_NAME, c_channel);
        control_channel_append_str(file_name, c_channel, n_len);
        control_channel_send(c_channel);

        break;
    }

    case SERVER:
    {
        if(!control_channel_read_expect(c_channel, GET) || 
           !control_channel_read_expect(c_channel, FTP_FILE_NAME))
        {
            operation_abort(c_channel);

            return 0;
        }

        control_channel_get_str(c_channel, file_name, &n_len);        
        break;
    }
    
    default:
    {
        operation_abort(c_channel);
        return -1;
    }

    }

    file = fopen(file_name, "rb");

    if (file == NULL)
    {
        LOG(SERVER_LOG, "Error opening file\n");
        return 0;
    } 

    while(byte = fread(buf, sizeof(buf), BUF_LEN, file) > 0)
    {
        data_channel_set_header(d_channel, ident++, BUF_LEN, 
                                byte == BUF_LEN, SEND, 1);
        data_channel_append_str(buf, d_channel, byte);
        data_channel_send(d_channel);
    }

    if(byte < 0)
    {
        LOG(SERVER_LOG, "Error sending file\n");
        control_channel_append_ftp_type(ABORT, c_channel);
        control_channel_send(c_channel);

        return 0;
    }

    control_channel_append_ftp_type(SUCCESS, c_channel);
    control_channel_send(c_channel);  

    return 1;
}

int data_append(control_channel* c_channel, data_channel* d_channel,
                endpoint_type type, char* file_name, unsigned int n_len,
                char* remote_file_name, unsigned int rn_len)
{
    if(!remote_file_exist(c_channel, type, remote_file_name, rn_len))
        return 0;
    
    switch (type)
    {
    case CLIENT:
    {
        control_channel_append_ftp_type(APPEND, c_channel);
        control_channel_send(c_channel);

        control_channel_append_ftp_type(FTP_REMOTE_FILE_NAME, c_channel);
        control_channel_append_str(remote_file_name, c_channel, rn_len);
        control_channel_send(c_channel);

        FILE* file = fopen(file_name, "rb");
        char buf[BUF_LEN];
        int byte;
        int ident = -1;

        if (file == NULL)
        {
            LOG(CLIENT_LOG, "Error opening file\n");
            operation_abort(c_channel);
            return 0;
        } 

        while(byte = fread(buf, sizeof(buf), BUF_LEN, file) > 0)
        {
            data_channel_set_header(d_channel, ident++, BUF_LEN, 
                                    byte == BUF_LEN, APPEND, 1);
            data_channel_append_str(buf, d_channel, byte);
            data_channel_send(d_channel);
        }

        if(byte < 0)
        {
            LOG(SERVER_LOG, "Error sending file\n");
            operation_abort(c_channel);

            return 0;
        }

        control_channel_append_ftp_type(SUCCESS, c_channel);
        control_channel_send(c_channel);
        
        break;
    }
    case SERVER:
    {
        bool last_fragment = 0;
        char* file_name;
        int n_len;
        char* buf;
        int b_len;

        if(!control_channel_read_expect(c_channel, APPEND) || 
        !control_channel_read_expect(c_channel, FTP_REMOTE_FILE_NAME))
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

            if(!not_exist(file_name)) 
                delete_file(file_name);
                
            append_file(file_name, buf);
            last_fragment = d_channel->data_in->p_header->fragment_offset;
        }

        if(!control_channel_read_expect(c_channel, SUCCESS))
        {
            remove(file_name);
            LOG(SERVER_LOG, "Error when getting file\n");
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
}

int data_newer(control_channel* c_channel, data_channel* d_channel,
               socket_ftp* c_socket, socket_ftp* d_socket,
               char* file_name, int n_len, endpoint_type type)
{
    char* rm_modtime, *lc_modtime;
    struct tm* rm_datetime, *lc_datetime;
    unsigned int *rm_len, *lc_len;

    switch (type)
    {
    case CLIENT:
    {
        if(!remote_modtime(c_channel, type, file_name, &n_len, rm_modtime, rm_len ))
        {
            LOG(CLIENT_LOG, "Fail to get mod time\n");

            return 0;
        }

        local_modtime(file_name, &n_len, lc_modtime, lc_len);

        convert_to_datetime(rm_modtime, rm_datetime);
        convert_to_datetime(lc_modtime, lc_datetime);

        if(is_older(rm_datetime, lc_datetime))
        {
            LOG(CLIENT_LOG, "Server file is older than local file\nAbort the operation\n");
            
            return 0;
        }

        if(!data_conn(c_channel, d_channel, c_socket, d_socket, CLIENT))
        {
            LOG(CLIENT_LOG, "Fail to open data connection\n");
            return 0;
        }

        get(c_channel, d_channel, file_name, &n_len, CLIENT);

        break;
    }
    case SERVER:
    {
        if(!remote_modtime(c_channel, type, file_name, &n_len, rm_modtime, rm_len ) ||
           !put(c_channel, d_channel, file_name, n_len, SERVER))
        {
            LOG(SERVER_LOG, "Fail to send modtime\n");
            operation_abort(c_channel);

            return 0;
        }

        put(c_channel, d_channel, file_name, n_len, SERVER);
        
        break;
    }

    default:
    {
        operation_abort(c_channel);
        return -1;
    }

    }

    return 0;
}

int data_reget(control_channel* c_channel, data_channel* d_channel,
               socket_ftp* c_socket, socket_ftp* d_socket,
               char* file_name, int n_len, endpoint_type type)
{
    int remote_size, local_size;

    switch (type)
    {
    case CLIENT:
    {
        if(!local_get_size(file_name, &n_len, &local_size) || 
           !remote_get_size(c_channel, file_name, n_len, &remote_size, CLIENT))
        {
            LOG(CLIENT_LOG, "Fail to get size\n");
            return 0;
        }

        if(remote_size < local_size)
        {
            LOG(CLIENT_LOG, "Remote file has smaller size than local. Abort\n");
            return 0;
        }

        if(!get(c_channel, d_channel,file_name, &n_len, CLIENT))
        {
            LOG(CLIENT_LOG, "Failed to get file from remote server\n");
            return 0;
        }

        break;
    }
    case SERVER:
    {
        if(!put(c_channel, d_channel,file_name, n_len, SERVER))
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