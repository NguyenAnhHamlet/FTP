#ifndef __PACKET__FTP__
#define __PACKET__FTP__

#include "buffer.h"
#include "ftp_type.h"
#include <stdbool.h>

typedef struct 
{
    int    identification;
    int    tt_len;                  // tt len of the packet 
    int    data_len;                // tt len of data in buf
    int    fragment_offset;
    int    packet_type;
    int    compression_mode;

    Buffer* header_buf;             // header's data only

} packet_header;

typedef struct 
{
    packet_header* p_header;
    Buffer* buf;
    struct timeval time_out;
    int out_port;
    int in_port;
    int len;
} Packet;

void packet_init(Packet* packet, unsigned int out_port, 
                 unsigned int packet_type,
                 unsigned int in_port);
void packet_set_port(Packet* packet, unsigned int in_port, 
                     unsigned int out_port);
void packet_set_nonblocking(Packet* packet);
void packet_destroy(Packet* packet);
void set_packet_compress(Packet* packet);
void unset_packet_compress(Packet* packet);
void packet_set_timeout(Packet* packet, unsigned int timeout);
int packet_read(Packet* packet);
int packet_read_header(Packet* packet);
int packet_wait(Packet* packet);
int packet_read_expect(Packet* packet, unsigned int expect_value);
int packet_send(Packet* packet);
int packet_send_wait(Packet* packet);
int packet_append_str(char* str, Packet* packet, unsigned int len);
int packet_append_bignum(BIGNUM** bignum, Packet* packet);
int packet_append_int(int num, Packet* packet);
void packet_append_header(Packet* packet);
void packet_set_header( Packet*packet, int identification,
                        int tt_len, int fragment_offset,
                        int packet_type, int compression_mode,
                        int data_len);
unsigned int packet_get_int(Packet* packet);
int packet_get_str(Packet* packet, char* str, unsigned int* len);
int packet_get_bignum(BIGNUM** bignum, Packet* packet);
void packet_clear_data(Packet* packet);
void packet_free(Packet* packet);
int packet_get_tt_len(Packet* packet);
int packet_get_data_len(Packet* packet);
void packet_header_init(Packet* packet);
int packet_header_len(Packet* packet);
void packet_send_header(Packet* packet);
void packet_convert_header(Packet* packet);
void packet_set_fragment(Packet* packet, int fragment_offset);
void packet_clear_header(Packet* packet);
void packet_set_identification(Packet* packet, int ident);
void packet_set_data_len(Packet* packet, int data_len);
void packet_set_tt_len(Packet* packet, int total_len);
int packet_get_ident(Packet* packet);

#endif