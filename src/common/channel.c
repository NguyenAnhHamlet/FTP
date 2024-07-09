#include "channel.h"
#include "packet.h"

void control_channel_init(  control_channel* channel,
                            unsigned int out_port, unsigned int in_port,
                            endpoint_type conn,
                            unsigned int cypher_type)
{
    channel->conn = conn;
    channel->cypher_type = cypher_type;

    channel->data_in = (Packet*) malloc(sizeof(Packet));
    channel->data_in = (Packet*) malloc(sizeof(Packet));

    channel->data_in->in_port = in_port;
    channel->data_int->out_port = -1;
    channel->data_out->out_port = out_port;
    channel->data_int->in_port = -1;
}

void control_channel_init_socket_ftp(control_channel* channel,
                                    socket_ftp* out_socket, 
                                    socket_ftp* in_socket,
                                    endpoint_type conn,
                                    unsigned int cypher_type)
{
    control_channel_init(   channel, out_socket->PORT, 
                            in_socket->PORT, conn, cypher_type)
}

void control_channel_set_port(control_channel* channel, unsigned int in_port, unsigned int out_port)
{
    packet_set_port(channel->data_in, in_port, -1);
    packet_set_port(channel->data_in, -1, out_port);
}

void control_channel_set_cipher(control_channel* channel, unsigned int cypher_type)
{
    packet_set_cipher(channel->data_in, cypher_type);
    packet_set_cipher(channel->data_out, cypher_type);
}

void control_channel_set_nonblocking(control_channel* channel)
{
    packet_set_nonblocking(channel->data_in);
    packet_set_nonblocking(channel->data_out);
}

void control_channel_destroy(control_channel* channel)
{
    packet_destroy(channel->data_in);
    packet_destroy(channel->data_out);

    free(channel);
}

void set_control_channel_compress(control_channel* channel)
{
    set_packet_compress(channel->data_out);
}

void unset_control_channel_compress(control_channel* channel)
{
    unset_packet_compress(channel->data_out);
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

void control_channel_send(control_channel* channel)
{
    packet_send_wait(channel->data_out);
}
int control_channel_send_wait(control_channel* channel)
{
    return packet_send_wait(channel->data_out);
}

int control_channel_append_str(char* str, control_channel* channel, unsigned int len)
{
    return packet_append_str(str, channel->data_out, len);
}

int control_channel_append_bignum(BIGNUM* bignum, control_channel* channel)
{
    return packet_append_bignum(bignum, channel->data_out);
}

int control_channel_append_int(int num, control_channel* channel)
{
    return packet_append_int(num, channel->data_out);
}

unsigned int control_channel_get_int(control_channel* channel)
{
    return packet_get_int(channel->data_in);
}

int control_channel_get_str(control_channel* channel, char* str, unsigned int* len)
{
    return packet_get_str(channel->data_in, str, len);
}

int control_channel_get_bignum(BIGNUM* bignum, control_channel* channel)
{
    return packet_get_bignum(bignum, channel->data_in);
}
