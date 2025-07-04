#ifndef __CHANNEL__
#define __CHANNEL__

#include <stdio.h>
#include "secure/rsa.h"
#include "buffer.h"
#include "common.h"
#include "secure/aescipher.h"
#include "common/packet.h"
#include "common/socket_ftp.h"
#include "log/ftplog.h"

#define DEFAULT_CHANNEL_TMOUT 20

// 
// Control channel
// 

typedef enum 
{
    RSAK = 1,
    ED25519K = 2
} pubkey_type;

typedef enum
{
    DHK = 1,
    ECK = 2
} kexkey_type;

typedef struct
{
    endpoint_type conn;   
    
    Packet* data_in;
    Packet* data_out;

} control_channel;


// 
// data channel
// 

typedef struct 
{
    cipher_context* cipher_ctx; 
    Packet* data_in;
    Packet* data_out;

} data_channel;


// 
// channel context
// 
typedef struct 
{   
    cipher_context* cipher_ctx; 
    data_channel* d_channel;
    control_channel* c_channel;
    socket_ftp* c_socket;
    socket_ftp* d_socket;
    socket_ftp* d_socket_listening;
    endpoint_type type;
    pubkey_type pkeytype;
    char username[32];

    // Data assigned by client side 
    char *source;
    int source_len;

    // Data returned that will be read by client side 
    Buffer* retb; 
    char* ret;
    unsigned int ret_len;
    unsigned int ret_int;
    unsigned int log_type;

    // control port and data port
    unsigned int control_port;
    unsigned int data_port; 

    unsigned int prompt;
    unsigned int passmode;

    // read status of current transfer process 
    unsigned int pipe_fd[MAXPROCCESS][2];
    unsigned int usedpipe[MAXPROCCESS + 1];
    unsigned int max_pipe_fd;
    Stack free_pipe;

    
} channel_context;

void channel_context_init(channel_context* channel_ctx, 
                          cipher_context* cipher_ctx, 
                          data_channel* d_channel, 
                          control_channel* c_channel, 
                          socket_ftp* c_socket, socket_ftp* d_socket, 
                          endpoint_type type, ftplog_type log_type);

void channel_context_set_pub(channel_context* channel_ctx, pubkey_type pkeytype );

int get_free_pipe(channel_context* channel_ctx);

// 
// Control channel
// 

void control_channel_init(  control_channel* channel,
                            unsigned int out_port, unsigned int in_port,
                            endpoint_type conn,
                            cipher_context* cipher_ctx);
void control_channel_init_socket_ftp(control_channel* channel,
                                    socket_ftp* out_socket, 
                                    socket_ftp* in_socket,
                                    endpoint_type conn,
                                    cipher_context* cipher_ctx);
void control_channel_set_time_out(control_channel* channel, unsigned int tmout);
void control_channel_set_port(control_channel* channel, unsigned int in_port, 
                              unsigned int out_port);
void control_channel_set_nonblocking(control_channel* channel);
void set_control_channel_compress(control_channel* channel);
void unset_control_channel_compress(control_channel* channel);
int  control_channel_set_header(control_channel* channel,
                            int  identification,
                            int  tt_len,
                            int fragment_offset,
                            int packet_type,
                            int compression_mode,
                            int data_len);
int control_channel_read(control_channel* channel);
int control_channel_read_header(control_channel* channel);
int control_channel_read_expect(control_channel* channel, 
                                unsigned int expect_value);
int control_channel_send(control_channel* channel);
int control_channel_send_wait(control_channel* channel);
int control_channel_append_str(char* str, control_channel* channel, 
                               unsigned int len);
int control_channel_append_bignum(BIGNUM** bignum, control_channel* channel);
int control_channel_append_int(int num, control_channel* channel);
int control_channel_append_ftp_type(int ftp_type, control_channel* channel);
int control_channel_get_int(control_channel* channel);
int control_channel_get_str(control_channel* channel, char* str, unsigned int* len);
int control_channel_get_bignum(BIGNUM** bignum, control_channel* channel);
void control_channel_destroy(control_channel* c_channel);
void control_channel_append_header(control_channel* channel,
                                   int identification,
                                   int tt_len, int fragment_offset,
                                   int packet_type, int compression_mode,
                                   int data_len);
int control_channel_get_data_len_out(control_channel* c_channel);
int control_channel_get_data_len_in(control_channel* c_channel);
int control_channel_get_ftp_type_in(control_channel* c_channel);
int control_channel_get_ftp_type_out(control_channel* c_channel);
int control_channel_get_sockfd_in(control_channel* c_channel);
int control_channel_get_sockfd_out(control_channel* c_channel);
int control_channel_get_str_out(control_channel* channel, char* str, 
                                unsigned int* len);
void control_channel_clean_data_out(control_channel* channel);
void control_channel_clean_data_in(control_channel* channel);
void control_channel_clear_header_in(control_channel* c_channel);
void control_channel_clear_header_out(control_channel* c_channel);

// 
// data channel
// 

void data_channel_init( data_channel* channel,
                        unsigned int out_port, 
                        unsigned int in_port,
                        cipher_context* cipher_ctx);
void data_channel_init_socket_ftp(data_channel* channel,
                                  socket_ftp* out_socket, 
                                  socket_ftp* in_socket,
                                  endpoint_type conn,
                                  cipher_context* cipher_ctx);
void data_channel_decrypt(data_channel* channel);
void data_channel_encrypt(data_channel* channel);
void set_data_channel_compress(data_channel* channel);
void unset_data_channel_compress(data_channel* channel);
void data_channel_clean_dataout(data_channel* channel);
int data_channel_read(data_channel* channel);
int data_channel_read_header(data_channel* channel);
int data_channel_read_expect(data_channel* channel, 
                             unsigned int expect_value);
int data_channel_send(data_channel* channel);
int data_channel_send_wait(data_channel* channel);
int data_channel_append_str(char* str, data_channel* channel, 
                            unsigned int len);
int data_channel_append_bignum(BIGNUM** bignum, data_channel* channel);
int data_channel_append_int(int num, data_channel* channel);
int data_channel_set_header(data_channel* channel,
                            int  identification,
                            int  tt_len,
                            int fragment_offset,
                            int packet_type,
                            int compression_mode,
                            int data_len);
int data_channel_get_int(data_channel* channel);
int data_channel_get_str(data_channel* channel, char* str, 
                         unsigned int* len);
int data_channel_get_bignum(BIGNUM** bignum, data_channel* channel);
void data_channel_clean_datain(data_channel* channel);
void data_channel_destroy(data_channel* d_channel);
void data_channel_set_time_out(data_channel* channel, 
                               unsigned int tmout);
void data_channel_append_header(data_channel* channel,
                                int identification,
                                int tt_len, int fragment_offset,
                                int packet_type, int compression_mode,
                                int data_len);
int data_channel_get_data_len_out(data_channel* d_channel);
int data_channel_get_data_len_in(data_channel* d_channel);
void data_channel_set_ctx(data_channel* d_channel, cipher_context* ctx);
void data_channel_append_ftp_type(data_channel* d_channel, unsigned int ftp_type);
int data_channel_get_ftp_type_in(data_channel* d_channel);
int data_channel_get_ftp_type_out(data_channel* d_channel);
int data_channel_get_ident_in(data_channel* d_channel);
int data_channel_get_ident_out(data_channel* d_channel);
void data_channel_set_fragment_in(data_channel* d_channel, int fragment_offset);
void data_channel_clear_header_in(data_channel* d_channel);
void data_channel_set_identification_in(data_channel* d_channel, int ident);
void data_channel_set_data_len_in(data_channel* d_channel, int data_len);
void data_channel_set_tt_len_in(data_channel* d_channel, int total_len);
void data_channel_set_fragment_out(data_channel* d_channel, int fragment_offset);
void data_channel_clear_header_out(data_channel* d_channel);
void data_channel_set_identification_out(data_channel* d_channel, int ident);
void data_channel_set_data_len_out(data_channel* d_channel, int data_len);
void data_channel_set_tt_len_out(data_channel* d_channel, int total_len);
int data_channel_get_fragment_in(data_channel* d_channel);
int data_channel_get_fragment_out(data_channel* d_channel);

#endif