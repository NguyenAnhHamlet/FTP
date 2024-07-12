#ifndef __CHANNEL__
#define __CHANNEL__

#include <stdio.h>
#include "edcsa.h"
#include "hmac.h"
#include "rsa.h"
#include "buffer.h"
#include "common.h"
#include "aescipher.h"

// 
// Control channel
// 

typedef struct
{
    endpoint_type conn;             //client or server
    unsigned int cypher_type;       

    RSA* rsa_public_key;
    RSA* rsa_private_key;

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
// Control channel
// 

void control_channel_init(  control_channel* channel,
                            unsigned int out_port, unsigned int in_port,
                            endpoint_type conn,
                            unsigned int cypher_type);

void control_channel_init_socket_ftp(control_channel* channel,
                                    socket_ftp* out_socket, 
                                    socket_ftp* in_socket,
                                    endpoint_type conn,
                                    unsigned int cypher_type);

void control_channel_set_port(control_channel* channel, unsigned int in_port, unsigned int out_port);
void control_channel_set_cipher(control_channel* channel, unsigned int cypher_type);
void control_channel_set_nonblocking(control_channel* channel);
void control_channel_destroy(control_channel* channel);
void set_control_channel_compress(control_channel* channel);
void unset_control_channel_compress(control_channel* channel);

int control_channel_read(control_channel* channel);
int control_channel_read_header(control_channel* channel);
int control_channel_read_expect(control_channel* channel, unsigned int expect_value);
void control_channel_send(control_channel* channel);
int control_channel_send_wait(control_channel* channel);

int control_channel_append_str(char* str, control_channel* channel, unsigned int len);
int control_channel_append_bignum(BIGNUM* bignum, control_channel* channel);
int control_channel_append_int(int num, control_channel* channel);
<<<<<<< HEAD
int control_channel_append_ftp_type(int ftp_type, control_channel* channel);

int control_channel_get_int(control_channel* channel);
=======

unsigned int control_channel_get_int(control_channel* channel);
>>>>>>> 14a728ce950b1f1d31e5c2ca3e3777f82f231bd5
int control_channel_get_str(control_channel* channel, char* str, unsigned int* len);
int control_channel_get_bignum(BIGNUM* bignum, control_channel* channel);

// 
// data channel
// 

void data_channel_init( data_channel* channel,
                        unsigned int out_port, unsigned int in_port,
                        cipher_context* cipher_ctx);

void data_channel_init_socket_ftp(data_channel* channel,
                                  socket_ftp* out_socket, 
                                  socket_ftp* in_socket,
                                  endpoint_type conn,
<<<<<<< HEAD
                                  unsigned int cypher_type);
=======
                                  unsigned int cypher_type)
>>>>>>> 14a728ce950b1f1d31e5c2ca3e3777f82f231bd5
                        
void data_channel_decrypt(data_channel* channel, char* outbuf, unsigned int out_len);
void data_channel_encrypt(data_channel* channel, char* outbuf, unsigned int out_len);
void set_data_channel_compress(data_channel* channel);
void unset_data_channel_compress(data_channel* channel);

int data_channel_read(data_channel* channel);
int data_channel_read_header(data_channel* channel);
int data_channel_read_expect(data_channel* channel, unsigned int expect_value);
void data_channel_send(data_channel* channel);
int data_channel_send_wait(data_channel* channel);

int data_channel_append_str(char* str, data_channel* channel, unsigned int len);
int data_channel_append_bignum(BIGNUM* bignum, data_channel* channel);
int data_channel_append_int(int num, data_channel* channel);

<<<<<<< HEAD
int data_channel_set_header(data_channel* channel,
                            int  identification,
                            int  tt_len,
                            bool fragment_offset,
                            int packet_type,
                            int compression_mode);

int data_channel_get_int(data_channel* channel);
int data_channel_get_str(data_channel* channel, char* str, unsigned int* len);
int data_channel_get_bignum(BIGNUM* bignum, data_channel* channel);
void data_channel_clean_datain_clear(data_channel* channel);
=======
unsigned int data_channel_get_int(data_channel* channel);
int data_channel_get_str(data_channel* channel, char* str, unsigned int* len);
int data_channel_get_bignum(BIGNUM* bignum, data_channel* channel);
>>>>>>> 14a728ce950b1f1d31e5c2ca3e3777f82f231bd5

#endif