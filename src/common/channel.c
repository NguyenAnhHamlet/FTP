#include "common/channel.h"
#include "common/packet.h"
#include "log/ftplog.h"
#include <signal.h>

void channel_context_init(channel_context* channel_ctx, cipher_context* cipher_ctx, 
                     data_channel* d_channel, control_channel* c_channel, 
                     socket_ftp* c_socket, socket_ftp* d_socket, 
                     endpoint_type type, ftplog_type log_type)
{
    channel_ctx->cipher_ctx = cipher_ctx;
    channel_ctx->d_channel = d_channel;
    channel_ctx->c_channel = c_channel;
    channel_ctx->c_socket = c_socket;
    channel_ctx->d_socket = d_socket;
    channel_ctx->type = type;
    
    channel_ctx->source = NULL;
    channel_ctx->source_len = 0;
    channel_ctx->ret = NULL;
    channel_ctx->ret_len = 0;
    channel_ctx->log_type = log_type;
    channel_ctx->prompt = 0;
    channel_ctx->passmode = 1;
    channel_ctx->retb = (Buffer*) malloc(sizeof(Buffer));
    buffer_init(channel_ctx->retb);
}

void channel_context_set_pub(channel_context* channel_ctx, pubkey_type pkeytype )
{
    channel_ctx->pkeytype = pkeytype;
}

int get_free_pipe(channel_context* channel_ctx)
{
    int ret = 0;
    int checkmax = 0;
start:
    if(!is_stack_empty(&channel_ctx->free_pipe))
    {
        int ret = top(&channel_ctx->free_pipe);
        pop(&channel_ctx->free_pipe);
    }
    else 
    {
        if(channel_ctx->max_pipe_fd > MAXPROCCESS && checkmax == 0)
        {
            for(int i =0; i< MAXPROCCESS+ 1; i++ )
            {
                if((kill(channel_ctx->usedpipe[i], 0) == 0))
                {
                    channel_ctx->usedpipe[i] = 0;
                    close(channel_ctx->pipe_fd[i][0]);
                    close(channel_ctx->pipe_fd[i][1]);
                    push(&channel_ctx->free_pipe, i);
                    checkmax = 1;
                }
            }

            goto start;
        }
        else if(channel_ctx->max_pipe_fd < MAXPROCCESS)
        {
            channel_ctx->max_pipe_fd++;
            ret = channel_ctx->max_pipe_fd - 1;
        }
        else 
        {
            return -1;
        }

    }

    channel_ctx->usedpipe[ret] = 1;

    return ret;
}

void control_channel_init(  control_channel* channel,
                            unsigned int out_port, unsigned int in_port,
                            endpoint_type conn,
                            cipher_context* cipher_ctx)
{
    channel->conn = conn;

    channel->data_in = (Packet*) malloc(sizeof(Packet));
    channel->data_out = (Packet*) malloc(sizeof(Packet));

    packet_init(channel->data_in, in_port, 0, in_port);
    packet_init(channel->data_out, out_port, 0, in_port);

    channel->data_in->in_port = in_port;
    channel->data_in->out_port = 0;
    channel->data_out->out_port = out_port;
    channel->data_out->in_port = 0;
}

int control_channel_get_data_len_out(control_channel* c_channel)
{
    return packet_get_data_len(c_channel->data_out);
}

int control_channel_get_data_len_in(control_channel* c_channel)
{
    return packet_get_data_len(c_channel->data_in); 
}

void control_channel_init_socket_ftp(control_channel* channel,
                                    socket_ftp* out_socket, 
                                    socket_ftp* in_socket,
                                    endpoint_type conn,
                                    cipher_context* cipher_ctx)
{
    control_channel_init(   channel, out_socket->sockfd, 
                            in_socket->sockfd, conn, cipher_ctx);
}

void control_channel_append_header(control_channel* channel,
                                   int identification,
                                   int tt_len, int fragment_offset,
                                   int packet_type, int compression_mode,
                                   int data_len)
{
    packet_set_header(channel->data_out, identification, 
                      tt_len, fragment_offset, packet_type, 
                      compression_mode, data_len);
}

void control_channel_set_port(control_channel* channel, 
                              unsigned int in_port, 
                              unsigned int out_port)
{
    packet_set_port(channel->data_in, in_port, -1);
    packet_set_port(channel->data_in, -1, out_port);
}

void control_channel_set_time_out(control_channel* channel, 
                              unsigned int tmout)
{
    packet_set_timeout(channel->data_in, tmout);
    packet_set_timeout(channel->data_out, tmout);
}

void control_channel_set_nonblocking(control_channel* channel)
{
    packet_set_nonblocking(channel->data_in);
    packet_set_nonblocking(channel->data_out);
}

void control_channel_destroy(control_channel* c_channel)
{
    packet_destroy(c_channel->data_in);
    packet_destroy(c_channel->data_out);

    // Not sure if the channel was dynamically created 
    // or not, user should manually free the channel instead
    // free(c_channel);
}

void set_control_channel_compress(control_channel* channel)
{
    set_packet_compress(channel->data_out);
}

void unset_control_channel_compress(control_channel* channel)
{
    unset_packet_compress(channel->data_out);
}

int control_channel_set_header(control_channel* channel,
                            int  identification,
                            int  tt_len,
                            int fragment_offset,
                            int packet_type,
                            int compression_mode,
                            int data_len)
{
    packet_set_header(channel->data_out, identification,
                      tt_len, fragment_offset, packet_type,
                      compression_mode, data_len);
}

int control_channel_read(control_channel* channel)
{
    return packet_read(channel->data_in);
}

int control_channel_read_header(control_channel* channel)
{
    return packet_read_header(channel->data_in);
}

int control_channel_read_expect(control_channel* channel, 
                                unsigned int expect_value)
{
    return packet_read_expect(channel->data_in, expect_value);
}

int control_channel_send(control_channel* channel)
{
    return packet_send_wait(channel->data_out);
}
int control_channel_send_wait(control_channel* channel)
{
    return packet_send_wait(channel->data_out);
}

int control_channel_append_str(char* str, control_channel* channel, unsigned int len)
{
    return packet_append_str(str, channel->data_out, len);
}

int control_channel_append_bignum(BIGNUM** bignum, control_channel* channel)
{
    return packet_append_bignum(bignum, channel->data_out);
}

int control_channel_append_int(int num, control_channel* channel)
{
    return packet_append_int(num, channel->data_out);
}

int control_channel_get_int(control_channel* channel)
{
    return packet_get_int(channel->data_in);
}

int control_channel_get_str(control_channel* channel, char* str, unsigned int* len)
{
    return packet_get_str(channel->data_in, str, len);
}

int control_channel_get_str_out(control_channel* channel, char* str, unsigned int* len)
{
    return packet_get_str(channel->data_out, str, len);
}

int control_channel_get_bignum(BIGNUM** bignum, control_channel* channel)
{
    return packet_get_bignum(bignum, channel->data_in);
}

void control_channel_clean_data_out(control_channel* channel)
{
    packet_clear_data(channel->data_out);
}

void control_channel_clean_data_in(control_channel* channel)
{
    packet_clear_data(channel->data_in);
}

int control_channel_append_ftp_type(int ftp_type, control_channel* channel)
{
    control_channel_append_header(channel, -1, 0, 
                                  -1, ftp_type, 0, 0);
}

int control_channel_get_ftp_type_in(control_channel* c_channel)
{
    return c_channel->data_in->p_header->packet_type;
}

int control_channel_get_ftp_type_out(control_channel* c_channel)
{
    return c_channel->data_out->p_header->packet_type;
}

int control_channel_get_sockfd_in(control_channel* c_channel)
{
    return c_channel->data_in->in_port;
}   

int control_channel_get_sockfd_out(control_channel* c_channel)
{
    return c_channel->data_in->out_port;
}

// DATA

void data_channel_init( data_channel* channel,
                        unsigned int out_port, 
                        unsigned int in_port,
                        cipher_context* cipher_ctx)
{
    channel->data_in = (Packet*) malloc(sizeof(Packet));
    channel->data_out = (Packet*) malloc(sizeof(Packet));

    packet_init(channel->data_in, out_port, 0, in_port);
    packet_init(channel->data_out, out_port, 0, in_port);

    set_packet_compress(channel->data_in);
    set_packet_compress(channel->data_out);

    channel->data_in->in_port = in_port;
    channel->data_in->out_port = 0;
    channel->data_out->out_port = out_port;
    channel->data_out->in_port = 0;

    channel->cipher_ctx = cipher_ctx;
}

void data_channel_append_header(data_channel* channel,
                                int identification,
                                int tt_len, int fragment_offset,
                                int packet_type, int compression_mode,
                                int data_len)
{
    packet_set_header(channel->data_out, identification, 
                      tt_len, fragment_offset, packet_type, 
                      compression_mode, data_len);
}

void data_channel_init_socket_ftp(data_channel* channel,
                                  socket_ftp* out_socket, 
                                  socket_ftp* in_socket,
                                  endpoint_type conn,
                                  cipher_context* cipher_ctx)
{
    data_channel_init(channel, out_socket->sockfd, 
                      in_socket->sockfd, cipher_ctx);
}

void data_channel_decrypt(data_channel* channel)
{
    if(channel->data_in->p_header->data_len <= 0) return;

    char* buf, *outbuf;
    int b_len, out_len;

    outbuf = (char*) malloc(buffer_len(channel->data_in->buf) + EVP_MAX_BLOCK_LENGTH);
    buf = (char*) malloc(buffer_len(channel->data_in->buf) );

    memset(outbuf, 0, buffer_len(channel->data_in->buf) + EVP_MAX_BLOCK_LENGTH);
    memset(buf, 0, buffer_len(channel->data_in->buf));

    packet_get_str(channel->data_in, buf, &b_len);
    aes_cypher_decrypt( channel->cipher_ctx, buf, 
                        b_len, outbuf, &out_len);
    data_channel_clean_datain(channel);
    packet_append_str(outbuf, channel->data_in, out_len);

    free(outbuf);
    free(buf);
}

void data_channel_encrypt(data_channel* channel)
{
    char* buf, *outbuf;
    int b_len, out_len, block_size;

    outbuf = (char*) malloc(buffer_len(channel->data_out->buf) + EVP_MAX_BLOCK_LENGTH);
    buf = (char*) malloc(buffer_len(channel->data_out->buf) );

    memset(outbuf, 0, buffer_len(channel->data_out->buf));
    memset(buf, 0, buffer_len(channel->data_out->buf));

    packet_get_str(channel->data_out, buf, &b_len);
    aes_cypher_encrypt( channel->cipher_ctx, buf, b_len, outbuf, &out_len);
    data_channel_clean_dataout(channel);
    data_channel_append_str(outbuf, channel, out_len);

    free(outbuf);
    free(buf);
}

void set_data_channel_compress(data_channel* channel)
{
    set_packet_compress(channel->data_out);
}

void unset_data_channel_compress(data_channel* channel)
{
    unset_packet_compress(channel->data_out);
}

int data_channel_read(data_channel* channel)
{
    if(!packet_read(channel->data_in)) return 0;
    data_channel_decrypt(channel);

    return 1;
}

int data_channel_read_header(data_channel* channel)
{
    return packet_read_header(channel->data_in);
}

int data_channel_read_expect(data_channel* channel, unsigned int expect_value)
{
    if(!packet_read_expect(channel->data_in, expect_value)) return 0;
    data_channel_decrypt(channel);

    return 1;
}

int data_channel_send(data_channel* channel)
{
    data_channel_encrypt(channel);
    return packet_send_wait(channel->data_out);
}

int data_channel_send_wait(data_channel* channel)
{
    LOG(SERVER_LOG, "AVAI 9\n");
    data_channel_encrypt(channel);
    return packet_send_wait(channel->data_out);
}

int data_channel_append_str(char* str, data_channel* channel, unsigned int len)
{
    return packet_append_str(str, channel->data_out, len);
}

int data_channel_append_bignum(BIGNUM** bignum, data_channel* channel)
{
    return packet_append_bignum(bignum, channel->data_out);
}

int data_channel_append_int(int num, data_channel* channel)
{
    return packet_append_int(num, channel->data_out);
}

int data_channel_get_int(data_channel* channel)
{
    return packet_get_int(channel->data_in);
}

int data_channel_get_str(data_channel* channel, char* str, unsigned int* len)
{
    return packet_get_str(channel->data_in, str, len);
}

int data_channel_get_bignum(BIGNUM** bignum, data_channel* channel)
{
    return packet_get_bignum(bignum, channel->data_in);
}


int data_channel_set_header(data_channel* channel,
                            int  identification,
                            int  tt_len,
                            int fragment_offset,
                            int packet_type,
                            int compression_mode,
                            int data_len )
{
    packet_set_header(channel->data_out, identification,
                      tt_len, fragment_offset, packet_type,
                      compression_mode, data_len);
}

void data_channel_clean_datain(data_channel* channel)
{
    packet_clear_data(channel->data_in);
}

void data_channel_clean_dataout(data_channel* channel)
{
    packet_clear_data(channel->data_out);
}

void data_channel_destroy(data_channel* d_channel)
{
    packet_destroy(d_channel->data_in);
    packet_destroy(d_channel->data_out);
    
    // Not sure if the channel was dynamically created 
    // or not, user should manually free the channel instead
    // free(d_channel);
}

void data_channel_set_time_out(data_channel* channel, 
                           unsigned int tmout)
{
    packet_set_timeout(channel->data_in, tmout);
    packet_set_timeout(channel->data_out, tmout);
}

int data_channel_get_data_len_out(data_channel* d_channel)
{
    return packet_get_data_len(d_channel->data_out);
}

int data_channel_get_data_len_in(data_channel* d_channel)
{
    return packet_get_data_len(d_channel->data_in); 
}

void data_channel_set_ctx(data_channel* d_channel, cipher_context* ctx)
{   
    d_channel->cipher_ctx = ctx;
}

void data_channel_append_ftp_type(data_channel* d_channel, unsigned int ftp_type)
{
    data_channel_append_header(d_channel, -1, 0, 
                                  -1, ftp_type, 1, 0);
}

int data_channel_get_ftp_type_in(data_channel* d_channel)
{
    return d_channel->data_in->p_header->packet_type;
}

int data_channel_get_ftp_type_out(data_channel* d_channel)
{
    d_channel->data_out->p_header->packet_type;
}

int data_channel_get_ident_in(data_channel* d_channel)
{
    return packet_get_ident(d_channel->data_in);
}

int data_channel_get_ident_out(data_channel* d_channel)
{
    return packet_get_ident(d_channel->data_out);
}

void data_channel_set_fragment_in(data_channel* d_channel, int fragment_offset)
{
    packet_set_fragment(d_channel->data_in, fragment_offset);
}

void data_channel_clear_header_in(data_channel* d_channel)
{
    packet_clear_header(d_channel->data_in);
}

void data_channel_set_identification_in(data_channel* d_channel, int ident)
{
    packet_set_identification(d_channel->data_in, ident);
}

void data_channel_set_data_len_in(data_channel* d_channel, int data_len)
{
    packet_set_data_len(d_channel->data_in, data_len);
}

void data_channel_set_tt_len_in(data_channel* d_channel, int total_len)
{
    packet_set_tt_len(d_channel->data_in, total_len);
}

void data_channel_set_fragment_out(data_channel* d_channel, int fragment_offset)
{
    packet_set_fragment(d_channel->data_out, fragment_offset);
}

void data_channel_clear_header_out(data_channel* d_channel)
{
    packet_clear_header(d_channel->data_out);
}

void data_channel_set_identification_out(data_channel* d_channel, int ident)
{
    packet_set_identification(d_channel->data_out, ident);
}

void data_channel_set_data_len_out(data_channel* d_channel, int data_len)
{
    packet_set_data_len(d_channel->data_out, data_len);
}

void data_channel_set_tt_len_out(data_channel* d_channel, int total_len)
{
    packet_set_tt_len(d_channel->data_out, total_len);
}

int data_channel_get_fragment_in(data_channel* d_channel)
{
    return d_channel->data_in->p_header->fragment_offset;
}

int data_channel_get_fragment_out(data_channel* d_channel)
{
    return d_channel->data_out->p_header->fragment_offset;
}