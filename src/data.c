#include "data.h"
#include "common/channel.h"
#include "common/file.h"
#include "cmd.h"
#include "common/ftp_type.h"
#include "common/packet.h"
#include "control.h"
#include <time.h>
#include "algo/algo.h"
#include "common/file.h"
#include "log/ftplog.h"

int data_conn( channel_context* channel_ctx )
{
    switch (channel_ctx->type)
    {
    case CLIENT:
    {
        // client send the FTP_CONN ask server to establish the data channel
        control_channel_append_ftp_type(FTP_CONN, channel_ctx->c_channel);
        control_channel_send(channel_ctx->c_channel);

        if(control_channel_read_expect(channel_ctx->c_channel, FTP_ACK) <= 0 )
        {
            LOG(CLIENT_LOG, "Fail to establish the data connection\n");
            operation_abort(channel_ctx->c_channel);
            return 0;
        }

        // the data channel has been established by server, connect now
        channel_ctx->d_socket = create_ftp_socket(channel_ctx->c_socket->ip_addr, 
                                                  channel_ctx->c_socket->endpoint_addr->sin_family, 
                                                  CLIENT, PORT_DATA, DATA, cre_socket());
                                     
        data_channel_init_socket_ftp(channel_ctx->d_channel, channel_ctx->d_socket, channel_ctx->d_socket, 
                                     CLIENT, channel_ctx->cipher_ctx);
        data_channel_set_time_out(channel_ctx->d_channel, DEFAULT_CHANNEL_TMOUT);

        // Done, send FTP_ACK
        control_channel_append_ftp_type(FTP_ACK, channel_ctx->c_channel);
        control_channel_send_wait(channel_ctx->c_channel);

        LOG(CLIENT_LOG, "Established data connection\n");

        break;
    }

    case SERVER:
    {
        if(!control_channel_read_expect(channel_ctx->c_channel, FTP_CONN))
        {
            LOG(SERVER_LOG, "Did not receive the connection code, code: %d\n", 
                control_channel_get_ftp_type_in(channel_ctx->c_channel));
            return 0;
        }

        // Open litening and waiting for connection from client
        channel_ctx->d_socket_listening = create_ftp_socket(NULL, AF_INET, SERVER, PORT_DATA, DATA, cre_socket());
        // Send FTP_ACK to notify client
        control_channel_append_ftp_type(FTP_ACK, channel_ctx->c_channel);
        control_channel_send(channel_ctx->c_channel);

        unsigned int d_socket = accept_new_connection_ftp(channel_ctx->d_socket_listening);

        // see if peer is correct, in case there is incorrect peer trying to connect, 
        // cease the operation
        if (!is_peer_correct(d_socket, channel_ctx->c_channel->data_in->in_port))
        {
            LOG(SERVER_LOG, "SOCKFD: %d %d\n", channel_ctx->c_socket->sockfd, channel_ctx->c_channel->data_in->in_port);
            LOG(SERVER_LOG, "Received the connection from incorrect ip address");
            close(channel_ctx->d_socket_listening->sockfd);
            destroy_ftp_socket(channel_ctx->d_socket_listening);
            close(d_socket);
            control_channel_append_ftp_type(ABORT, channel_ctx->c_channel);
            control_channel_send_wait(channel_ctx->c_channel);
            return 0;
        }

        // Don't listen to new connection, this door is shut down
        close(channel_ctx->d_socket_listening->sockfd);
        destroy_ftp_socket(channel_ctx->d_socket_listening);
        
        data_channel_init(channel_ctx->d_channel, d_socket, d_socket, channel_ctx->cipher_ctx);
        data_channel_set_time_out(channel_ctx->d_channel, DEFAULT_CHANNEL_TMOUT);

        // wait for FTP_ACK from client to signify the connection has been 
        // established successfully
        if(!control_channel_read_expect(channel_ctx->c_channel, FTP_ACK))
        { 
            LOG(SERVER_LOG, "Failed to receive ACK from client\n");
            operation_abort(channel_ctx->c_channel);
            return 0;
        }

        LOG(SERVER_LOG, "Established data connection\n");

        break;
    }
    
    default:
    {
        operation_abort(channel_ctx->c_channel);
        break;
    }

    }

    return 1;
}

int get(channel_context* channel_ctx)
{
    char* buf, *base_file_name, *file_name = NULL;
    int b_len;

    switch (channel_ctx->type)
    {
    case CLIENT:
    {
        // establish the data channel first
        if(!data_conn(channel_ctx))
            return 0;

        // send file's name over to server 
        control_channel_append_ftp_type(FTP_FILE_NAME, channel_ctx->c_channel);
        control_channel_append_str(channel_ctx->source, channel_ctx->c_channel, 
                                   channel_ctx->source_len);

        control_channel_send(channel_ctx->c_channel);

        // check the file's existence on remote server
        if( !control_channel_read_expect(channel_ctx->c_channel, FILE_EXIST))
        {
            LOG(CLIENT_LOG, "File does not exit on remote side\n");
            LOG(SERVER_LOG, "File %d: \n", control_channel_get_ftp_type_in(channel_ctx->c_channel));
            operation_abort(channel_ctx->c_channel);
            
            return 0;
        }

        break;
    }

    case SERVER:
    {
        // establish the data channel first
        if(!data_conn(channel_ctx))
            return 0;

        // receive file's name
        if(!control_channel_read_expect(channel_ctx->c_channel, FTP_FILE_NAME))
        {
            operation_abort(channel_ctx->c_channel);

            return 0;
        }

        int data_len = control_channel_get_data_len_in(channel_ctx->c_channel) +1;
        file_name = (char*) malloc(data_len);
        channel_ctx->source = file_name;
        memset(channel_ctx->source, 0, data_len);
        control_channel_get_str(channel_ctx->c_channel, channel_ctx->source, 
                                &channel_ctx->source_len);
        
        break;
    }
    
    default:
    {
        operation_abort(channel_ctx->c_channel);
        return -1;
    }

    }

    // read data and append into file
    if(!data_channel_read_expect(channel_ctx->d_channel, SEND))
    {
        LOG(CLIENT_LOG, "Did not receive READ code\n");
        operation_abort(channel_ctx->c_channel);
        return 0;
    }

    int recv_len = 0;
    int data_len = data_channel_get_data_len_in(channel_ctx->d_channel);
    buf = (char*) malloc(data_len + 1);
    memset(buf, 0, data_len + 1);
    data_channel_get_str(channel_ctx->d_channel, buf, &recv_len);

    // Add check to see if data len the same as recv len
    if(data_len != recv_len)
    {
        LOG(channel_ctx->log_type, "Not received enough data from server."
            "Expected: %d vs Received : %d\n", data_len, recv_len);
        operation_abort(channel_ctx->c_channel);
        free(buf);
        return 0;
    }

    basename(channel_ctx->source, &base_file_name);

    if (!not_exist(base_file_name))
    {
        // Remove old file
        remove(base_file_name);
    }

    create_file(base_file_name);
    append_file(base_file_name, buf, data_len);

    if(!control_channel_read_expect(channel_ctx->c_channel, SUCCESS))
    {
        // Do not remove file when failure occurs, enable REGET
        // remove(base_file_name);
        LOG(channel_ctx->log_type, "Error when getting file %s from remote server\n", 
            channel_ctx->source);
        operation_abort(channel_ctx->c_channel);
        free(buf);
        return 0;
    }

    // destroy data channel and socket
    close(channel_ctx->d_channel->data_in->in_port);
    packet_destroy(channel_ctx->d_channel->data_in);
    packet_destroy(channel_ctx->d_channel->data_out);
    if(channel_ctx->type == CLIENT)
        destroy_ftp_socket(channel_ctx->d_socket);

    free(buf);
    if(file_name) free(file_name);

    return 1;
}

int put(channel_context* channel_ctx)
{
    FILE* file;
    char buf[BUF_LEN];
    int byte;
    int ident = -1;  
    char* file_name = NULL; 

    switch (channel_ctx->type)
    {
    case CLIENT:
    {
        // establish the data channel first
        if(!data_conn(channel_ctx))
            return 0;

        // send file's name over to server
        control_channel_append_ftp_type(FTP_FILE_NAME, channel_ctx->c_channel);
        control_channel_append_str(channel_ctx->source, channel_ctx->c_channel,
                                   channel_ctx->source_len);
        control_channel_send(channel_ctx->c_channel);

        break;
    }

    case SERVER:
    {
        // establish the data channel first
        if(!data_conn(channel_ctx))
            return 0;
        
        // get file's name
        if(!control_channel_read_expect(channel_ctx->c_channel, FTP_FILE_NAME))
        {
            operation_abort(channel_ctx->c_channel);

            return 0;
        }

        int data_len = control_channel_get_data_len_in(channel_ctx->c_channel) + 1;
        file_name = (char*) malloc(data_len);
        memset(file_name, 0, data_len);
        channel_ctx->source = file_name;
        control_channel_get_str(channel_ctx->c_channel, channel_ctx->source, 
                                &channel_ctx->source_len);        
        break;
    }
    
    default:
    {
        operation_abort(channel_ctx->c_channel);
        return -1;
    }

    }

    file = fopen(channel_ctx->source, "rb"); 

    // file does not exist or there is error in I/O operation
    if (file == NULL)
    {
        LOG(channel_ctx->log_type, "Error opening file\n");
        LOG(channel_ctx->log_type, strerror(errno));
        control_channel_append_ftp_type(FILE_NOT_EXIST, channel_ctx->c_channel);
        control_channel_send_wait(channel_ctx->c_channel);
        return 0;
    } 

    if(channel_ctx->type == SERVER)
    {
        // File does exist, send code to confirm operation - server side only
        control_channel_append_ftp_type(FILE_EXIST, channel_ctx->c_channel);
        control_channel_send_wait(channel_ctx->c_channel);
    }

    // read and send file over to other endpoint
    data_channel_append_ftp_type(channel_ctx->d_channel, SEND);
    while((byte = fread(buf, sizeof(char), BUF_LEN, file)) > 0)
    {
        data_channel_append_str(buf, channel_ctx->d_channel, byte);
    }
        
    data_channel_send_wait(channel_ctx->d_channel);

    // error, abort
    if (ferror(file))
    {
        LOG(channel_ctx->log_type, "Error sending file\n");
        control_channel_append_ftp_type(ABORT, channel_ctx->c_channel);
        control_channel_send(channel_ctx->c_channel);
        return 0;
    }

    // send code to endpoint, notify send file successfully
    control_channel_append_ftp_type(SUCCESS, channel_ctx->c_channel);
    control_channel_send(channel_ctx->c_channel);  

    // destroy data channel and socket
    close(channel_ctx->d_channel->data_in->in_port);
    packet_destroy(channel_ctx->d_channel->data_in);
    packet_destroy(channel_ctx->d_channel->data_out);
    if(channel_ctx->type == CLIENT)
        destroy_ftp_socket(channel_ctx->d_socket);

    if(file_name) free(file_name);

    return 1;
}

int data_append(channel_context* channel_ctx)
{   
    switch (channel_ctx->type)
    {
    case CLIENT:
    {
        // Update design 
        // Read and seperate the arg into local_name and remote_name
        char* local_name = channel_ctx->source;
        char* remote_name = strchr(channel_ctx->source, ' ');

        if(!remote_name)
        {
            LOG(CLIENT_LOG, "arguments lack remote_name, it contains only %s\n",
                channel_ctx->source);
            return 0;
        }

        remote_name = 0;
        remote_name++;

        // establish the data channel first
        if(!data_conn(channel_ctx))
            return 0;

        // send file's name to server
        control_channel_append_ftp_type(FTP_REMOTE_FILE_NAME, channel_ctx->c_channel);
        control_channel_append_str(remote_name, channel_ctx->c_channel,
                                  strlen(remote_name));
        control_channel_send(channel_ctx->c_channel);

        FILE* file = fopen(local_name, "rb");
        char buf[BUF_LEN];
        int byte;
        int ident = -1;

        if (file == NULL)
        {
            LOG(CLIENT_LOG, "Error opening file\n");
            operation_abort(channel_ctx->c_channel);
            return 0;
        } 

        // read and send file over to other endpoint
        data_channel_append_ftp_type(channel_ctx->d_channel, SEND);
        while((byte = fread(buf, sizeof(char), BUF_LEN, file)) > 0)
        {
            data_channel_append_str(buf, channel_ctx->d_channel, byte);
        }
            
        data_channel_send_wait(channel_ctx->d_channel);

        if(byte < 0)
        {
            LOG(SERVER_LOG, "Error sending file\n");
            operation_abort(channel_ctx->c_channel);

            return 0;
        }

        control_channel_append_ftp_type(SUCCESS, channel_ctx->c_channel);
        control_channel_send(channel_ctx->c_channel);
        
        break;
    }
    case SERVER:
    {
        char file_name[BUF_LEN];
        int n_len;
        char* buf;
        int b_len;

        // establish the data channel first
        if(!data_conn(channel_ctx))
            return 0;

        // get file's name
        if(!control_channel_read_expect(channel_ctx->c_channel, FTP_REMOTE_FILE_NAME))
        {
            LOG(SERVER_LOG, "Failed to received the remote file name from client side\n");
            operation_abort(channel_ctx->c_channel);
            return 0;
        }

        control_channel_get_str(channel_ctx->c_channel, file_name, &n_len);

        // in case file does not exist, create a brand new one
        if(not_exist(file_name)) 
            create_file(file_name);

        // read data and append into file
        int recv_len = 0;
        int data_len = data_channel_get_data_len_in(channel_ctx->d_channel);
        buf = (char*) malloc(data_len + 1);
        memset(buf, 0, data_len + 1);
        data_channel_read(channel_ctx->d_channel);
        data_channel_get_str(channel_ctx->d_channel, buf, &recv_len);

        // Add check to see if data len the same as recv len
        if(data_len != recv_len)
        {
            LOG(channel_ctx->log_type, "Not received enough data from server."
                "Expected: %d vs Received : %d\n", data_len, recv_len);
            operation_abort(channel_ctx->c_channel);
            free(buf);
            return 0;
        }

        append_file(file_name, buf, data_len);

        if(!control_channel_read_expect(channel_ctx->c_channel, SUCCESS))
        {
            remove(file_name);
            LOG(SERVER_LOG, "Error when getting file\n");
            operation_abort(channel_ctx->c_channel);
            free(buf);

            return 0;
        }

        free(buf);

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

int data_newer(channel_context* channel_ctx)
{
    char rm_modtime[BUF_LEN], lc_modtime[BUF_LEN], *local_file_name;
    struct tm rm_datetime, lc_datetime;
    unsigned int rm_len, lc_len;

    switch (channel_ctx->type)
    {
    case CLIENT:
    {
        if(!remote_modtime(channel_ctx))
        {
            LOG(CLIENT_LOG, "Fail to get mod time\n");
            operation_abort(channel_ctx->c_channel);
            return 0;
        }

        basename(channel_ctx->source, &local_file_name);
        local_modtime(local_file_name, &channel_ctx->source_len, 
                      lc_modtime, &lc_len);

        convert_to_datetime(rm_modtime, &rm_datetime);
        convert_to_datetime(lc_modtime, &lc_datetime);

        if(is_older(&rm_datetime, &lc_datetime))
        {
            LOG(CLIENT_LOG, "Server file is older than local file " 
                            "Abort the operation\n");

            // notify server about this to prevent further unneccesary operation
            // in server side
            operation_abort(channel_ctx->c_channel);
            return 0;
        }

        control_channel_append_ftp_type(FTP_ACK, channel_ctx->c_channel);
        control_channel_send(channel_ctx->c_channel);

        get(channel_ctx);

        break;
    }
    case SERVER:
    {
        if(!remote_modtime(channel_ctx))
        {
            LOG(SERVER_LOG, "Fail to send modtime\n");
            operation_abort(channel_ctx->c_channel);
            return 0;
        }

        // check if the operation should be continued or not
        if(!control_channel_read_expect(channel_ctx->c_channel, FTP_ACK))
        {
            LOG(SERVER_LOG, "Abort operation by client side\n");
            return 0;
        }

        put(channel_ctx);
        
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

int data_reget(channel_context* channel_ctx)
{
    switch (channel_ctx->type)
    {
    case CLIENT:
    {
        // establish the data channel first
        if(!data_conn(channel_ctx))
            return 0;

        FILE* fp;
        char* base = NULL;
        basename(channel_ctx->source, &base);
        read_file(base, &fp);

        // get the offset of the end of file in client side
        fseek(fp, 0, SEEK_END);
        int offset = ftell(fp);
        if(offset < 0)
        {
            LOG(CLIENT_LOG, "Fail to seek the offset\n");
            operation_abort(channel_ctx->c_channel);
            return 0;
        }

        // got the offset value, send over file name and offset
        control_channel_append_ftp_type(REGET, channel_ctx->c_channel);
        control_channel_append_int(offset, channel_ctx->c_channel);
        control_channel_append_str(channel_ctx->source, 
                                   channel_ctx->c_channel,
                                   channel_ctx->source_len);
        control_channel_send(channel_ctx->c_channel);

        // read data into buffer
        if(!data_channel_read_expect(channel_ctx->d_channel, REGET))
        {
            LOG(CLIENT_LOG, "Failed to receive data, received CODE: %d\n", 
                control_channel_get_ftp_type_in(channel_ctx->c_channel));
            operation_abort(channel_ctx->c_channel);
            return 0;
        }

        int data_len = data_channel_get_data_len_in(channel_ctx->d_channel);
        int recv_len = 0;
        char* data = (char*) malloc(data_len + 1); 
        memset(data, 0, data_len + 1);
        data_channel_get_str(channel_ctx->d_channel, data ,&recv_len);
        if(data_len != recv_len )
        {
            LOG(CLIENT_LOG, "Not received enough data from server."
                "Expected: %d vs Received : %d\n", data_len, recv_len);
            operation_abort(channel_ctx->c_channel);
            free(data);
            return 0;
        }

        for(int i=0; i < data_len; i++)
            if(data[i] == '\n') printf("Y %d\n", i);

        // append data into file
        append_file(base, data, data_len);

        if(!control_channel_read_expect(channel_ctx->c_channel, SUCCESS))
        {
            LOG(SERVER_LOG, "Failed to receive success, received CODE: %d\n", 
                control_channel_get_ftp_type_in(channel_ctx->c_channel));
            operation_abort(channel_ctx->c_channel);
            return 0;
        }

        // happy now
        // destroy data channel and socket
        free(data);
        close(channel_ctx->d_channel->data_in->in_port);
        packet_destroy(channel_ctx->d_channel->data_in);
        packet_destroy(channel_ctx->d_channel->data_out);
        destroy_ftp_socket(channel_ctx->d_socket);

        break;
    }
    case SERVER:
    {
        // establish the data channel first
        if(!data_conn(channel_ctx))
            return 0;

        FILE* fp;
        int byte;
        char buf[BUF_LEN];

        // get offset from client 
        if(!control_channel_read_expect(channel_ctx->c_channel, REGET))
        {
            LOG(SERVER_LOG, "Failed to receive offset, received CODE: %d\n", 
                control_channel_get_ftp_type_in(channel_ctx->c_channel));
            operation_abort(channel_ctx->c_channel);
            return 0;
        }

        int data_len = control_channel_get_data_len_in(channel_ctx->c_channel);
        channel_ctx->source = (char*) malloc(data_len + 1);
        memset(channel_ctx->source, 0, data_len + 1);
        int offset = control_channel_get_int(channel_ctx->c_channel);
        control_channel_get_str(channel_ctx->c_channel, channel_ctx->source, 
                                &channel_ctx->source_len);
        if(offset < 0)
        {
            LOG(SERVER_LOG, "Value offset is not right\n");
            operation_abort(channel_ctx->c_channel);
            return 0;
        }

        read_file(channel_ctx->source, &fp);
        fseek(fp, offset, SEEK_SET);

        // read and send file over to other endpoint
        data_channel_append_ftp_type(channel_ctx->d_channel, REGET);
        while((byte = fread(buf, sizeof(char), BUF_LEN, fp)) > 0)
        {
            data_channel_append_str(buf, channel_ctx->d_channel, byte);
        }

        data_channel_send_wait(channel_ctx->d_channel);

        // error, abort
        if (ferror(fp))
        {
            LOG(SERVER_LOG, "Error sending file\n");
            control_channel_append_ftp_type(ABORT, channel_ctx->c_channel);
            control_channel_send(channel_ctx->c_channel);
            return 0;
        }

        // send code to endpoint, notify send file successfully
        control_channel_append_ftp_type(SUCCESS, channel_ctx->c_channel);
        control_channel_send(channel_ctx->c_channel);  

        // happy now
        // destroy data channel and socket
        close(channel_ctx->d_channel->data_in->in_port);
        packet_destroy(channel_ctx->d_channel->data_in);
        packet_destroy(channel_ctx->d_channel->data_out);

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