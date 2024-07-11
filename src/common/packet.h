#ifndef __PACKET__FTP__
#define __PACKET__FTP__

#include "buffer.h"
#include "ftp_type.h"
#include <stdbool.h>

typedef struct 
{
    unsigned int    tt_len;
    unsigned int    identification;
    bool            fragment_offset;
    unsigned int    packet_type;
    unsigned int    compression_mode;

} packet_header;

typedef struct 
{
    packet_header* p_header;
    Buffer* buf;
    struct timeval time_out;
    unsigned int out_port;
    unsigned int in_port;
    int len;
} Packet;

void packet_init(Packet* packet, unsigned int out_port, unsigned int packet_type 
                 unsigned int in_port, unsigned int cypher_type );
void packet_set_port(Packet* packet, unsigned int in_port, unsigned int out_port);
void packet_set_cipher(Packet* packet, unsigned int cypher_type);
void packet_set_nonblocking(Packet* packet);
void packet_destroy(Packet* packet);
void set_packet_compress(Packet* packet);
void unset_packet_compress(Packet* packet);
void packet_set_timeout(Packet* packet, unsigned int timeout);

int packet_read(Packet* packet);
int packet_read_header(Packet* packet);
int packet_wait(Packet* packet);
int packet_read_expect(Packet* packet, unsigned int expect_value);
void packet_send(Packet* packet);
int packet_send_wait(Packet* packet);

int packet_append_str(char* str, Packet* packet, unsigned int len);
int packet_append_bignum(BIGNUM* bignum, Packet* packet);
int packet_append_int(int num, Packet* packet);
void packet_append_header(Packet* packet);

unsigned int packet_get_int(Packet* packet);
int packet_get_str(Packet* packet, char* str, unsigned int* len);
int packet_get_bignum(BIGNUM* bignum, Packet* packet);

#endif