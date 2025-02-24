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
#include <glob.h>
#include <signal.h>
#include <readline/readline.h>
#include <libgen.h>

unsigned long total_bytes=0;

// passive mode
int data_conn( channel_context* channel_ctx )
{
    switch (channel_ctx->type)
    {
    case CLIENT:
    {
        // client send the FTP_CONN ask server to establish the data channel
        control_channel_append_ftp_type(FTP_PASV, channel_ctx->c_channel);
        control_channel_send(channel_ctx->c_channel);

        // receive the port number from server (PASSIVE mode)
        if(control_channel_read_expect(channel_ctx->c_channel, FTP_ACK) <= 0 )
        {
            LOG(CLIENT_LOG, "Fail to establish the data connection\n");
            operation_abort(channel_ctx->c_channel);
            return 0;
        }

        channel_ctx->data_port = control_channel_get_int(channel_ctx->c_channel);

        // the data channel has been established by server, connect now
        channel_ctx->d_socket = create_ftp_socket(channel_ctx->c_socket->ip_addr, 
                                                  channel_ctx->c_socket->endpoint_addr->sin_family, 
                                                  CLIENT, channel_ctx->data_port , DATA, cre_socket());
                                     
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
        if(!control_channel_read_expect(channel_ctx->c_channel, FTP_PASV))
        {
            LOG(SERVER_LOG, "Did not receive the connection code, code: %d\n", 
                control_channel_get_ftp_type_in(channel_ctx->c_channel));
            return 0;
        }

        // Open litening and waiting for connection from client
        channel_ctx->d_socket_listening = create_ftp_socket(NULL, AF_INET, SERVER, 
                                                            0, DATA, cre_socket());
                                                        
        // Send FTP_ACK to notify client with POrt number
        channel_ctx->data_port = port_number(socket_ftp_get_port(channel_ctx->d_socket_listening));
        control_channel_append_ftp_type(FTP_ACK, channel_ctx->c_channel);
        control_channel_append_int(channel_ctx->data_port, channel_ctx->c_channel);
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
    char *base_file_name = NULL, *file_name = NULL;
    total_bytes = 0;

    switch (channel_ctx->type)
    {
    case CLIENT:
    {
        if(channel_ctx->prompt)
        {
            char* ans = NULL;
            char ques[BUF_LEN];
            sprintf(ques, "get %s ? ", channel_ctx->source);
            ans = readline(ques);
            if(!ans || strncmp(ans, "y", 2))
            {
                operation_abort(channel_ctx->c_channel);
                return 0;
            }
        }

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
            LOG(channel_ctx->log_type, "Expected %d but got %d\n", 
                FTP_FILE_NAME, control_channel_get_ftp_type_in(channel_ctx->c_channel));
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

    base_file_name = basename(channel_ctx->source);

    if (!not_exist(base_file_name))
    {
        // Remove old file
        remove(base_file_name);
    }

    create_file(base_file_name);
    // read data and append into file 
    if(!get_file(channel_ctx, base_file_name))
    {
        LOG(channel_ctx->log_type, "Error when getting file %s from remote server\n", 
            channel_ctx->source);
        operation_abort(channel_ctx->c_channel);
        close(channel_ctx->d_channel->data_in->in_port);
        packet_destroy(channel_ctx->d_channel->data_in);
        packet_destroy(channel_ctx->d_channel->data_out);
        if(channel_ctx->type == CLIENT)
            destroy_ftp_socket(channel_ctx->d_socket);
        return 0;
    }

    // destroy data channel and socket
    close(channel_ctx->d_channel->data_in->in_port);
    packet_destroy(channel_ctx->d_channel->data_in);
    packet_destroy(channel_ctx->d_channel->data_out);
    if(channel_ctx->type == CLIENT)
        destroy_ftp_socket(channel_ctx->d_socket);

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
    total_bytes = 0;

    switch (channel_ctx->type)
    {
    case CLIENT:
    {
        if(channel_ctx->prompt)
        {
            char* ans = NULL;
            char ques[BUF_LEN];
            sprintf(ques, "get %s ? ", channel_ctx->source);
            ans = readline(ques);
            if(!ans || strncmp(ans, "y", 2))
            {
                operation_abort(channel_ctx->c_channel);
                return 0;
            }
        }

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
    if(!send_file(channel_ctx, file))
    {
        LOG(channel_ctx->log_type, "Failed to send file to endpoint\n");
        control_channel_append_ftp_type(ABORT, channel_ctx->c_channel);
        control_channel_send(channel_ctx->c_channel);
        close(channel_ctx->d_channel->data_in->in_port);
        packet_destroy(channel_ctx->d_channel->data_in);
        packet_destroy(channel_ctx->d_channel->data_out);
        if(channel_ctx->type == CLIENT)
            destroy_ftp_socket(channel_ctx->d_socket);
        if(file_name) free(file_name);
        return 0;
    }

    LOG(SERVER_LOG, "AVAI 2\n");

    // destroy data channel and socket
    close(channel_ctx->d_channel->data_in->in_port);
    packet_destroy(channel_ctx->d_channel->data_in);
    packet_destroy(channel_ctx->d_channel->data_out);
    if(channel_ctx->type == CLIENT)
        destroy_ftp_socket(channel_ctx->d_socket);

    if(file_name) free(file_name);

    LOG(SERVER_LOG, "AVAI 3\n");

    return 1;
}

int data_append(channel_context* channel_ctx)
{   
    total_bytes = 0;
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
            operation_abort(channel_ctx->c_channel);
            return 0;
        }

        *remote_name = 0;
        remote_name++;
        while(*remote_name == ' ') remote_name++;

        // establish the data channel first
        if(!data_conn(channel_ctx))
            return 0;

        // send file's name to server
        control_channel_append_ftp_type(FTP_REMOTE_FILE_NAME, channel_ctx->c_channel);
        control_channel_append_str(remote_name, channel_ctx->c_channel,
                                  strlen(remote_name));
        control_channel_send(channel_ctx->c_channel);

        FILE* file = fopen(local_name, "rb");

        LOG(SERVER_LOG, "NAME: %s\n", local_name);

        if (file == NULL)
        {
            LOG(CLIENT_LOG, "Error opening file\n");
            operation_abort(channel_ctx->c_channel);
            return 0;
        } 

        // read and send file over to other endpoint
        if(!send_file(channel_ctx, file))
        {
            LOG(channel_ctx->log_type, "Failed to append file to endpoint\n");
            control_channel_append_ftp_type(ABORT, channel_ctx->c_channel);
            control_channel_send(channel_ctx->c_channel);
            close(channel_ctx->d_channel->data_in->in_port);
            packet_destroy(channel_ctx->d_channel->data_in);
            packet_destroy(channel_ctx->d_channel->data_out);
            if(channel_ctx->type == CLIENT)
                destroy_ftp_socket(channel_ctx->d_socket);
            return 0;
        }
        
        break;
    }
    case SERVER:
    {
        char file_name[BUF_LEN];
        int n_len;

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
        LOG(SERVER_LOG, "APPEND1\n %s", file_name);                                                     

        // in case file does not exist, create a brand new one
        if(not_exist(file_name)) 
            create_file(file_name);

        // read data and append into file
        if(!get_file(channel_ctx, file_name))
        {
            LOG(channel_ctx->log_type, "Error when getting file %s from remote server\n", 
                channel_ctx->source);
            operation_abort(channel_ctx->c_channel);
            close(channel_ctx->d_channel->data_in->in_port);
            packet_destroy(channel_ctx->d_channel->data_in);
            packet_destroy(channel_ctx->d_channel->data_out);
            if(channel_ctx->type == CLIENT)
                destroy_ftp_socket(channel_ctx->d_socket);
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

int data_newer(channel_context* channel_ctx)
{
    total_bytes = 0;
    char* rm_modtime, lc_modtime[BUF_LEN], *local_file_name;
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

        rm_modtime = channel_ctx->ret;

        local_file_name = basename(channel_ctx->source);
        local_modtime(local_file_name, &channel_ctx->source_len, 
                      lc_modtime, &lc_len);

        convert_to_datetime(rm_modtime, &rm_datetime);
        convert_to_datetime(lc_modtime, &lc_datetime);

        if(is_older(&rm_datetime, &lc_datetime))
        {
            LOG(CLIENT_LOG, "Server file is older than local file " 
                            "Abort the operation\n");
            LOG(CLIENT_LOG, "rm_datetime : %s vs lc_modtime : %s\n", rm_modtime,
                lc_modtime);

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
    total_bytes = 0;
    switch (channel_ctx->type)
    {
    case CLIENT:
    {
        // establish the data channel first
        if(!data_conn(channel_ctx))
            return 0;

        FILE* fp;
        char* base = NULL;
        base = basename(channel_ctx->source);
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

        // read data 
        if(!get_file(channel_ctx, base))
        {
            LOG(channel_ctx->log_type, "Error when getting file %s from remote server\n", 
                channel_ctx->source);
            operation_abort(channel_ctx->c_channel);
            close(channel_ctx->d_channel->data_in->in_port);
            packet_destroy(channel_ctx->d_channel->data_in);
            packet_destroy(channel_ctx->d_channel->data_out);
            if(channel_ctx->type == CLIENT)
                destroy_ftp_socket(channel_ctx->d_socket);
            return 0;
        }

        // happy now
        // destroy data channel and socket
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

        int data_len = control_channel_get_data_len_in(channel_ctx->c_channel) + 1;
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

        if(send_file(channel_ctx, fp))
        {
            LOG(channel_ctx->log_type, "Failed to send file to endpoint\n");
            control_channel_append_ftp_type(ABORT, channel_ctx->c_channel);
            control_channel_send(channel_ctx->c_channel);
            close(channel_ctx->d_channel->data_in->in_port);
            packet_destroy(channel_ctx->d_channel->data_in);
            packet_destroy(channel_ctx->d_channel->data_out);
            free(channel_ctx->source);
            if(channel_ctx->type == CLIENT)
                destroy_ftp_socket(channel_ctx->d_socket);
            return 0;
        }

        // happy now
        // destroy data channel and socket
        close(channel_ctx->d_channel->data_in->in_port);
        packet_destroy(channel_ctx->d_channel->data_in);
        packet_destroy(channel_ctx->d_channel->data_out);
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

int send_file(channel_context* channel_ctx, FILE* file)
{
    // read the file, divide it into smaller buffer and send them 
    // consecutively and sequentially 

    // init essential infos 
    int ident = 0;              // which indicates the order 
    int fragment_offset = 0;    // which indicates last packet if set to 1
    char buf[BUF_LEN];
    int bytes;
    int ret_ident;

    // read and send file over to other endpoint
    while((bytes = fread(buf, sizeof(char), BUF_LEN, file)) > 0)
    {
        ident++;

        // LOG(SERVER_LOG, "AVAI 4 %d %d\n", fragment_offset, bytes);

        data_channel_clear_header_out(channel_ctx->d_channel);                           
        data_channel_append_ftp_type(channel_ctx->d_channel, SEND);     
        data_channel_clean_dataout(channel_ctx->d_channel);
        data_channel_append_str(buf, channel_ctx->d_channel, bytes);
        data_channel_set_identification_out(channel_ctx->d_channel, ident);
        data_channel_set_fragment_out(channel_ctx->d_channel, fragment_offset);
        data_channel_send_wait(channel_ctx->d_channel);

        // wait for ACK/NACK
        if(control_channel_read_expect(channel_ctx->c_channel, FTP_NACK))
        {
            LOG(channel_ctx->log_type, "Error sending file\n");
            LOG(channel_ctx->log_type, "Expected %d but got %d\n", 
                FTP_ACK, control_channel_get_ftp_type_in(channel_ctx->c_channel));
            control_channel_append_ftp_type(ABORT, channel_ctx->c_channel);
            control_channel_send(channel_ctx->c_channel);
            return 0;
        }

        LOG(SERVER_LOG, "AVAI 6\n");

        // read the ret identification code
        ret_ident = control_channel_get_int(channel_ctx->c_channel);

        if(ret_ident != ident )
        {
            LOG(channel_ctx->log_type, "Order of receiving packet is incorrect, abort\n");
            control_channel_append_ftp_type(ABORT, channel_ctx->c_channel);
            control_channel_send(channel_ctx->c_channel);
            return 0;
        }
    }

    total_bytes += bytes;

    if(feof(file))
    {
        fragment_offset = 1;
        data_channel_append_ftp_type(channel_ctx->d_channel, SEND);
        data_channel_set_fragment_out(channel_ctx->d_channel, fragment_offset);
        data_channel_send(channel_ctx->d_channel);
    }
    else
    {
        data_channel_append_ftp_type(channel_ctx->d_channel, ABORT);
        data_channel_send(channel_ctx->d_channel);
        return 0;
    }

    LOG(SERVER_LOG, "AVAI OUTSIDE %d %d\n", fragment_offset, bytes);

    if(!control_channel_read_expect(channel_ctx->c_channel, SUCCESS))
    {
        LOG(channel_ctx->log_type, "Failed to received file\n");
        LOG(channel_ctx->log_type, "Expected %d but received %d\n", 
            SEND, control_channel_get_ftp_type_in(channel_ctx->c_channel));
        control_channel_append_ftp_type(ABORT, channel_ctx->c_channel);
        control_channel_send(channel_ctx->c_channel);
        return 0;
    }

    LOG(SERVER_LOG, "AVAI END\n");

    return 1;

}

int get_file(channel_context* channel_ctx, char* base_file_name)
{
    int pre_ident = 0;
    int curr_ident = 0;
    int fragment_offset = 0;
    char buf[BUF_LEN];
    int recv_len;
    int data_len;

    while(fragment_offset == 0)
    {
        // set header to default 
        data_channel_clear_header_in(channel_ctx->d_channel);

        if(!data_channel_read_expect(channel_ctx->d_channel, SEND))
        {
            LOG(channel_ctx->log_type, "Expected %d but received %d\n", 
                SEND, data_channel_get_ftp_type_in(channel_ctx->d_channel));
            control_channel_append_ftp_type(FTP_NACK, channel_ctx->c_channel);
            control_channel_send(channel_ctx->c_channel);
            return 0;
        }

        fragment_offset = data_channel_get_fragment_in(channel_ctx->d_channel);
        
        if(fragment_offset)
            break;

        recv_len = 0;
        memset(buf, 0, data_len + 1);
        curr_ident = data_channel_get_ident_in(channel_ctx->d_channel);
        data_len = data_channel_get_data_len_in(channel_ctx->d_channel);
        data_channel_get_str(channel_ctx->d_channel, buf, &recv_len);

        // Add check to see if the order of arriving packets are correct
        if(curr_ident - pre_ident != 1)
        {
            LOG(channel_ctx->log_type, "The order of packets are not correct."
                                        " curr_ident : %d vs pre_ident : %d\n", 
                                        curr_ident, pre_ident);
            control_channel_append_ftp_type(FTP_NACK, channel_ctx->c_channel);
            control_channel_send(channel_ctx->c_channel);
            return 0;
        }

        // Add check to see if data len the same as recv len
        if(data_len != recv_len)
        {
            LOG(channel_ctx->log_type, "Not received enough data from server."
                "Expected: %d vs Received : %d\n", data_len, recv_len);
            control_channel_append_ftp_type(FTP_NACK, channel_ctx->c_channel);
            control_channel_send(channel_ctx->c_channel);
            return 0;
        }

        append_file(base_file_name, buf, data_len);
        total_bytes += data_len;
        pre_ident = curr_ident;

        // ACK 
        control_channel_append_ftp_type(FTP_ACK, channel_ctx->c_channel);
        control_channel_append_int(curr_ident, channel_ctx->c_channel);
        control_channel_send(channel_ctx->c_channel);
    }

    control_channel_append_ftp_type(SUCCESS, channel_ctx->c_channel);
    control_channel_send(channel_ctx->c_channel);

    return 1;
}

int mget(channel_context* channel_ctx)
{
    char* base_file_name = NULL;
    char* files_name = NULL;
    char* indiv_file = NULL;
    char* npos = NULL;
    unsigned int count = 0;

    switch (channel_ctx->type)
    {
    case CLIENT:
    {
        // Ask for all available files
        control_channel_append_ftp_type(MGET, channel_ctx->c_channel);
        control_channel_append_str(channel_ctx->source, channel_ctx->c_channel, 
                                   channel_ctx->source_len);
        control_channel_send(channel_ctx->c_channel);

        // get the series of files name from server
        if(!control_channel_read_expect(channel_ctx->c_channel, MGET))
        {
            LOG(channel_ctx->log_type, "Expected %d but got %d instead.\n", 
                MGET, control_channel_get_ftp_type_in(channel_ctx->c_channel));
            operation_abort(channel_ctx->c_channel);
            return 0;
        }

        unsigned int len = control_channel_get_data_len_in(channel_ctx->c_channel) + 1;
        files_name = (char*) malloc(len);
        memset(files_name, 0, len);

        if(!files_name)
        {
            LOG(channel_ctx->log_type, "Failed to allocate mem for files_name\n");
            operation_abort(channel_ctx->c_channel);
            return 0;
        } 

        control_channel_get_str(channel_ctx->c_channel, files_name, &len);
        LOG(channel_ctx->log_type, "files_name: %s\n", files_name);
        control_channel_append_ftp_type(MGET, channel_ctx->c_channel);

        if(channel_ctx->prompt)
        {
            indiv_file = files_name;
            npos++;
            while(*npos == ' ') npos++;

            while((npos = strchr(indiv_file, ' ')) || indiv_file)
            {
                if(npos)
                {
                    *npos = 0;
                    npos++;
                    while(*npos == ' ') npos++;
                }

                char* ans = NULL;
                char ques[BUF_LEN];
                sprintf(ques, "get %s ? ", channel_ctx->source);
                ans = readline(ques);
                if(!ans || strncmp(ans, "y", 2))
                {
                    count++;
                    control_channel_append_str(indiv_file, channel_ctx->c_channel, 
                                               strlen(indiv_file));
                }

                
                if(ans) free(ans);

                indiv_file = npos;
                if(!indiv_file || *indiv_file == '\0') break;
            }
            
            if(!count) 
            {
                LOG(channel_ctx->log_type, "No file in files_name\n");
                operation_abort(channel_ctx->c_channel);
                return 1;
            }

        }
        else
        {
            control_channel_append_str(files_name, channel_ctx->c_channel, len);
        }

        free(files_name); 
        len = control_channel_get_data_len_out(channel_ctx->c_channel) + 1;
        files_name = (char*) malloc(len); 
        memset(files_name, 0, len);
        control_channel_get_str_out(channel_ctx->c_channel, files_name, &len);
        
        control_channel_append_ftp_type(MGET, channel_ctx->c_channel);
        control_channel_append_str(files_name, channel_ctx->c_channel, len);
        control_channel_send(channel_ctx->c_channel);

        // establish the data channel first
        if(!data_conn(channel_ctx))
            return 0;

        indiv_file = files_name;
        while((npos = strchr(indiv_file, ' ')) || indiv_file)
        {
            if(npos) 
            {
                *npos = 0;
                npos++;
                while(*npos == ' ') npos++;
            }

            base_file_name = basename(indiv_file);
    
            if (!not_exist(base_file_name))
            {
                // Remove old file
                remove(base_file_name);
            }
        
            LOG(CLIENT, "Create file name : %s\n", indiv_file);
            create_file(base_file_name);
            // read data and append into file 
            if(!get_file(channel_ctx, base_file_name))
            {
                LOG(channel_ctx->log_type, "Error when getting file %s from remote server\n", 
                    channel_ctx->source);
                operation_abort(channel_ctx->c_channel);
                close(channel_ctx->d_channel->data_in->in_port);
                packet_destroy(channel_ctx->d_channel->data_in);
                packet_destroy(channel_ctx->d_channel->data_out);
                if(channel_ctx->type == CLIENT)
                    destroy_ftp_socket(channel_ctx->d_socket);
                return 0;
            }
    
            indiv_file = npos;
            if(!indiv_file || *indiv_file == '\0') break;
        }

        control_channel_append_ftp_type(SUCCESS, channel_ctx->c_channel);
        control_channel_send(channel_ctx->c_channel);

        break;
    }

    case SERVER:
    {
        // get files name from client
        if(!control_channel_read_expect(channel_ctx->c_channel, MGET))
        {
            LOG(channel_ctx->log_type, "Expected %d but got %d instead.\n", 
                MGET, control_channel_get_ftp_type_in(channel_ctx->c_channel));
                operation_abort(channel_ctx->c_channel);
            return 0;
        }
            
        unsigned int len = control_channel_get_data_len_in(channel_ctx->c_channel) + 1;
        files_name = (char*) malloc(len);
        memset(files_name, 0, len);

        if(!files_name)
        {
            LOG(channel_ctx->log_type, "Failed to allocate mem for files_name\n");
            operation_abort(channel_ctx->c_channel);
            return 0;
        } 
        
        control_channel_get_str(channel_ctx->c_channel, files_name, &len);
            
        // Check and send back all available files from server
        control_channel_clean_data_out(channel_ctx->c_channel);
        control_channel_append_ftp_type(MGET, channel_ctx->c_channel);

        indiv_file = files_name;
        while((npos = strchr(indiv_file, ' ')) || indiv_file)
        {
            if(npos) 
            {
                *npos = 0;
                npos++;
                while(*npos == ' ') npos++;
            }

            glob_t glob_result;
            int ret;

            ret = glob(indiv_file, 0, NULL, &glob_result);

            LOG(SERVER_LOG, "indiv_file outside: %s : %d\n", indiv_file, strlen(indiv_file));

            
            if(ret == 0)
            {
                for (size_t i = 0; i < glob_result.gl_pathc; i++) 
                {
                    control_channel_append_str(glob_result.gl_pathv[i], channel_ctx->c_channel, 
                                               strlen(glob_result.gl_pathv[i]));
                    control_channel_append_str(" ", channel_ctx->c_channel, 1);
                    LOG(SERVER_LOG, "indiv_file: %s\n", indiv_file);
                }
            }
            
            indiv_file = npos;
            if(!indiv_file || *indiv_file == '\0') break;
        }

        free(files_name);
        LOG(SERVER_LOG, "channel_ctx->c_channel->data_out : %s\n", channel_ctx->c_channel->data_out->buf->buf);
        control_channel_send_wait(channel_ctx->c_channel);

        if(!control_channel_read_expect(channel_ctx->c_channel, MGET))
        {
            LOG(channel_ctx->log_type, "Expected %d but got %d instead.\n", 
                MGET, control_channel_get_ftp_type_in(channel_ctx->c_channel));
                operation_abort(channel_ctx->c_channel);
            return 0;
        }

        len = control_channel_get_data_len_in(channel_ctx->c_channel) + 1;
        files_name = (char*) malloc(len);

        if(!files_name)
        {
            LOG(channel_ctx->log_type, "Failed to allocate mem for files_name\n");
            operation_abort(channel_ctx->c_channel);
            return 0;
        } 

        control_channel_get_str(channel_ctx->c_channel, files_name, &len);

        // establish the data channel first
        if(!data_conn(channel_ctx))
            return 0;

        indiv_file = files_name;
        while((npos = strchr(indiv_file, ' ')) || indiv_file)
        {
            if(npos) 
            {
                *npos = 0;
                npos++;
                while(*npos == ' ') npos++;
            }

            FILE* file = NULL;
            LOG(channel_ctx->log_type,"FILE: %s\n", indiv_file);
            read_file(indiv_file, &file);
            if(!send_file(channel_ctx, file))
            {
                LOG(channel_ctx->log_type, "Failed to send file to endpoint\n");
                control_channel_append_ftp_type(ABORT, channel_ctx->c_channel);
                control_channel_send(channel_ctx->c_channel);
                close(channel_ctx->d_channel->data_in->in_port);
                packet_destroy(channel_ctx->d_channel->data_in);
                packet_destroy(channel_ctx->d_channel->data_out);
                if(channel_ctx->type == CLIENT)
                    destroy_ftp_socket(channel_ctx->d_socket);
                return 0;
            }
            
            indiv_file = npos;
            if(!indiv_file || *indiv_file == '\0') break;
        }

        if(!control_channel_read_expect(channel_ctx->c_channel, SUCCESS))
        {
            LOG(channel_ctx->log_type, "Failed to received files\n");
            LOG(channel_ctx->log_type, "Expected %d but received %d\n", 
                SEND, control_channel_get_ftp_type_in(channel_ctx->c_channel));
            control_channel_append_ftp_type(ABORT, channel_ctx->c_channel);
            control_channel_send(channel_ctx->c_channel);
            return 0;
        }

        LOG(SERVER_LOG, "MGET 60\0");

        free(files_name);
        
        break;
    }
    
    default:
    {
        operation_abort(channel_ctx->c_channel);
        return -1;
    }

    }

    // destroy data channel and socket
    close(channel_ctx->d_channel->data_in->in_port);
    packet_destroy(channel_ctx->d_channel->data_in);
    packet_destroy(channel_ctx->d_channel->data_out);
    if(channel_ctx->type == CLIENT)
        destroy_ftp_socket(channel_ctx->d_socket);

    return 1;
}

int mput(channel_context* channel_ctx)
{
    FILE* file;
    int ident = -1;  
    char* files_name = NULL; 
    char* indiv_file = NULL;
    char* npos = NULL;

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

        // receive ACK
        if(!control_channel_read_expect(channel_ctx->c_channel, FTP_ACK))
        {
            LOG(channel_ctx->log_type, "Expected %d but received %d\n", 
                FTP_ACK, control_channel_get_ftp_type_in(channel_ctx->c_channel));
            operation_abort(channel_ctx->c_channel);
            return 0;
        }

        // Start sending files
        char* indiv_file = channel_ctx->source;
        char* npos = NULL;
        while((npos = strchr(indiv_file, ' ')) || indiv_file)
        {
            if(npos)
            {
                *npos = 0;
                npos++;
                while(*npos == ' ') npos++;
            }

            FILE* file = NULL;
            LOG(channel_ctx->log_type,"FILE: %s\n", indiv_file);
            read_file(indiv_file, &file);

            if(!send_file(channel_ctx, file))
            {
                LOG(channel_ctx->log_type, "Failed to send file to endpoint\n");
                control_channel_append_ftp_type(ABORT, channel_ctx->c_channel);
                control_channel_send(channel_ctx->c_channel);
                close(channel_ctx->d_channel->data_in->in_port);
                packet_destroy(channel_ctx->d_channel->data_in);
                packet_destroy(channel_ctx->d_channel->data_out);
                if(channel_ctx->type == CLIENT)
                    destroy_ftp_socket(channel_ctx->d_socket);
                return 0;
            }

            indiv_file = npos;
            if(!indiv_file || *indiv_file == '\0') break;

        }

        if(!control_channel_read_expect(channel_ctx->c_channel, SUCCESS))
        {
            LOG(channel_ctx->log_type, "Failed to received files\n");
            LOG(channel_ctx->log_type, "Expected %d but received %d\n", 
                SEND, control_channel_get_ftp_type_in(channel_ctx->c_channel));
            control_channel_append_ftp_type(ABORT, channel_ctx->c_channel);
            control_channel_send(channel_ctx->c_channel);
            return 0;
        }

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
            LOG(channel_ctx->log_type, "Expected %d but received %d\n", 
                FTP_FILE_NAME, control_channel_get_ftp_type_in(channel_ctx->c_channel));
            operation_abort(channel_ctx->c_channel);
            return 0;
        }

        int data_len = control_channel_get_data_len_in(channel_ctx->c_channel) + 1;
        files_name = (char*) malloc(data_len);
        memset(files_name, 0, data_len);
        control_channel_get_str(channel_ctx->c_channel, files_name, 
                                &data_len); 
        
        // send ACK
        control_channel_append_ftp_type(FTP_ACK, channel_ctx->c_channel);
        control_channel_send(channel_ctx->c_channel);

        // Start reading files
        char* indiv_file = files_name;
        char* npos = NULL;
        char* base_file_name = NULL;
        while((npos = strchr(indiv_file, ' ')) || indiv_file)
        {
            if(npos) 
            {
                *npos = 0;
                npos++;
                while(*npos == ' ') npos++;
            }

            base_file_name = basename(indiv_file);
    
            if (!not_exist(base_file_name))
            {
                // Remove old file
                remove(base_file_name);
            }
        
            LOG(CLIENT, "Create file name : %s\n", indiv_file);
            create_file(base_file_name);
            // read data and append into file 
            if(!get_file(channel_ctx, base_file_name))
            {
                LOG(channel_ctx->log_type, "Error when getting file %s from remote server\n", 
                    channel_ctx->source);
                operation_abort(channel_ctx->c_channel);
                close(channel_ctx->d_channel->data_in->in_port);
                packet_destroy(channel_ctx->d_channel->data_in);
                packet_destroy(channel_ctx->d_channel->data_out);
                if(channel_ctx->type == CLIENT)
                    destroy_ftp_socket(channel_ctx->d_socket);
                return 0;
            }
    
            indiv_file = npos;
            if(!indiv_file || *indiv_file == '\0') break;
        }

        control_channel_append_ftp_type(SUCCESS, channel_ctx->c_channel);
        control_channel_send(channel_ctx->c_channel);

        free(files_name);

        break;
    }
    
    default:
    {
        operation_abort(channel_ctx->c_channel);
        return -1;
    }

    }

    // destroy data channel and socket
    close(channel_ctx->d_channel->data_in->in_port);
    packet_destroy(channel_ctx->d_channel->data_in);
    packet_destroy(channel_ctx->d_channel->data_out);
    if(channel_ctx->type == CLIENT)
        destroy_ftp_socket(channel_ctx->d_socket);

    LOG(SERVER_LOG, "AVAI 3\n");

    return 1; 
}

int restart_get_file(channel_context* channel_ctx)
{
    switch (channel_ctx->type)
    {
    case CLIENT:
    {
        // establish the data channel first
        if(!data_conn(channel_ctx))
            return 0;

        FILE* fp = NULL;
        char* base = NULL;
        int offset;
        char* offset_str = NULL;
        base = basename(channel_ctx->source);
        read_file(base, &fp);

        if(!(offset_str = strchr(channel_ctx->source, ' ')))
        {
            LOG(CLIENT_LOG, "Lacked offset value\n");
            operation_abort(channel_ctx->c_channel);
            return 0;
        }

        while(*offset_str == ' ' ) offset_str++;

        offset = str_to_int(offset_str, strlen(offset_str));
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

        // read data 
        if(!get_file(channel_ctx, base))
        {
            LOG(channel_ctx->log_type, "Error when getting file %s from remote server\n", 
                channel_ctx->source);
            operation_abort(channel_ctx->c_channel);
            close(channel_ctx->d_channel->data_in->in_port);
            packet_destroy(channel_ctx->d_channel->data_in);
            packet_destroy(channel_ctx->d_channel->data_out);
            if(channel_ctx->type == CLIENT)
                destroy_ftp_socket(channel_ctx->d_socket);
            return 0;
        }

        // happy now
        // destroy data channel and socket
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

        int data_len = control_channel_get_data_len_in(channel_ctx->c_channel) + 1;
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

        if(send_file(channel_ctx, fp))
        {
            LOG(channel_ctx->log_type, "Failed to send file to endpoint\n");
            control_channel_append_ftp_type(ABORT, channel_ctx->c_channel);
            control_channel_send(channel_ctx->c_channel);
            close(channel_ctx->d_channel->data_in->in_port);
            packet_destroy(channel_ctx->d_channel->data_in);
            packet_destroy(channel_ctx->d_channel->data_out);
            free(channel_ctx->source);
            if(channel_ctx->type == CLIENT)
                destroy_ftp_socket(channel_ctx->d_socket);
            return 0;
        }

        // happy now
        // destroy data channel and socket
        close(channel_ctx->d_channel->data_in->in_port);
        packet_destroy(channel_ctx->d_channel->data_in);
        packet_destroy(channel_ctx->d_channel->data_out);
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