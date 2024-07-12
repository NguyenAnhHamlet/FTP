#include "packet.h"
#include <unistd.h>
#include <arpa/inet.h>
#include "compress.h"

void packet_init(Packet* packet, unsigned int out_port, unsigned int packet_type 
                 unsigned int in_port, unsigned int cypher_type )
{
    buffer_init(packet->buf);
    packet_set_port(in_port, out_port);
    packet->cypher_type = cypher_type;
    packet->packet_compress = FTP_DATA_NON_COMPRESS;
    packet->packet_type = packet_type;
}

void packet_set_port(Packet* packet, unsigned int in_port, unsigned int out_port)
{
    packet->in_port = in_port;
    packet->out_port = out_port;
}

void packet_set_cipher(Packet* packet, unsigned int cypher_type)
{
    packet->cypher_type = cypher_type;
}

void packet_set_nonblocking(Packet* packet)
{
    if (fcntl(packet->in_port, F_SETFL, O_NONBLOCK) < 0)
		error("fcntl O_NONBLOCK: %.100s", strerror(errno));

	if (packet->out_port != packet->in_port) 
    {
		if (fcntl(packet->out_port, F_SETFL, O_NONBLOCK) < 0)
			error("fcntl O_NONBLOCK: %.100s", strerror(errno));
	}
}

void packet_set_timeout(Packet* packet, unsigned int timeout)
{
    packet->time_out.tv_sec = timeout;
}

void packet_destroy(Packet* packet)
{
    buffer_free(packet->buf);
    free(packet);
}

void packet_send(Packet* packet)
{
    int len;
    char buf[BUF_LEN];
    if(packet->len > 0)
    {
        len = write(packet->out_port, buf, BUF_LEN); 

        if(len <= 0)
        {
            if (errno == EAGAIN)
				return;
            else
                fatal("Write failed: %.100s", strerror(errno));
        }

        packet->buf->offset += len;
    }
}

void set_packet_compress(Packet* packet)
{
    packet->packet_compress = 1;
}

void unset_packet_compress(Packet* packet)
{
    packet->packet_compress = 0;
}

int packet_read(Packet* packet)
{
    int len =0;
    int curr_len = 0;
    fd_set set;
    char buf[BUF_LEN];

    packet_read_header(packet);

    if(packet->packet_compress)
    {
        Buffer* outbuf;
        decompress(packet->buf, outbuf );
        buffer_clear(packet->buf);
        buffer_append_str(packet->buf, outbuf, buffer_len(outbuf));
    }

    while(packet->len - len > 0 )
    {
        FD_ZERO(&set);
		FD_SET(packet->in_port, &set);

        if(select(packet->in_port + 1, &set, NULL, NULL, NULL))
        {
            curr_len = read(packet->in_port, buf, BUF_LEN );

            if(!curr_len)
            {
                fatal("Connection closed\n");
            }

            if(curr_len < 0)
            {
                fatal("Read from socket failed: %.100s", strerror(errno));
            }

            buffer_append_str(packet->buf, buf, curr_len);
            len += curr_len;
        }
    }

    return 1;
}

int packet_read_header(Packet* packet)
{
    unsigned int    tt_len;
    unsigned int    identification;
    bool            fragment_offset;
    unsigned int    packet_type;
    unsigned int    compression_mode;

    char interger[4];

    for(int i=0; i < 5; i++)
    {
        if(recv(packet->in_port, interger, 4, 0) < 0)
            return 0;
        
        switch (i)
        {
        case 0:
            tt_len = GET_32BIT(interger);
            break;
        case 1:
            identification = GET_32BIT(interger);
            break;
        case 2:
            fragment_offset = GET_32BIT(interger);
            break;            
        case 3 :
            packet_type = GET_32BIT(interger);
            break;
        case 4 :
            compression_mode = GET_32BIT(interger);
        default:
            break;
        }
    }

    packet->p_header->tt_len = tt_len;
    packet->p_header->packet_type = packet_type;
    packet->p_header->compression_mode = compression_mode;
    packet->p_header->fragment_offset = fragment_offset;
    packet->p_header->identification = identification;

    return 1;
}

int packet_send_wait(Packet* packet)
{
    packet_append_header(packet);
    if(packet->p_header->packet_compress)
    {
        Buffer* outbuf;
        compress(packet->buf, outbuf );
        buffer_clear(packet->buf);
        buffer_append_str(packet->buf, outbuf, buffer_len(outbuf));
    }

    int curr_len = 0;
    fd_set set;

    while(buffer_len(packet->buf) > 0)
    {
		FD_ZERO(&set);
		FD_SET(packet->out_port, &set);
		select(packet->out_port + 1, NULL, &set, NULL, NULL);
        packet_send(packet);
    }
}

int packet_wait(Packet* packet)
{
    fd_set set;

    FD_ZERO(&set);
	FD_SET(packet->out_port, &set);
    int res = select(packet->out_port + 1, NULL, &set, NULL, packet->time_out);

    return res;
}

int packet_read_expect(Packet* packet, unsigned int expect_value)
{
    int packet_type;
    int res;
    
    res = packet_wait(packet);

    if(res == 0)
    {
        LOG("Time out receiving packet\n");
        return 0;       
    }

    if(res < 0)
    {
        LOG("Error in select function\n")
        return -1;
    }

    packet_read(packet);
    packet_type = packet->p_header->packet_type;

    return packet_type == expect_value ? 1 : 0;      
}

int packet_append_str(char* str, Packet* packet, unsigned int len)
{
    return buffer_append_str(packet->buf, str, len);
}

int packet_append_bignum(BIGNUM* bignum, Packet* packet)
{
    return buffer_put_bignum(packet->buf, bignum);
}

int packet_append_int(int num, Packet* packet)
{
    return buffer_put_int(packet->buf, num);
}

unsigned int packet_get_int(Packet* packet)
{
    return buffer_get_int(packet->buf );
}

int packet_get_str(Packet* packet, char* str, unsigned int* len)
{
    return buffer_get_data(packeet->buf, str, len);
}

int packet_get_bignum(BIGNUM* bignum, Packet* packet)
{
    return buffer_get_bignum(packeet->buf, bignum);
}

void packet_append_header(Packet* packet)
{
    buffer_put_int(packet->buf, packet->p_header->tt_len);
    buffer_put_int(packet->buf, packet->p_header->identification);
    buffer_put_int(packet->buf, packet->p_header->fragment_offset);
    buffer_put_int(packet->buf, packet->p_header->packet_type);
    buffer_put_int(packet->buf, packet->p_header->compression_mode);
}

void packet_set_header( Packet*packet, int identification,
                        int tt_len, bool fragment_offset,
                        int packet_type, int compression_mode)
{
    packet->p_header = (packet_header*) malloc(sizeof(packet_header));
    packet->p_header->compression_mode = compression_mode;
    packet->p_header->identification = identification;
    packet->p_header->tt_len = tt_len;
    packet->p_header->packet_type = packet_type;
    packet->p_header->fragment_offset = fragment_offset;
}

void packet_clear_data(Packet* packet)
{
    buffer_clear(packet->buf);
}

void packet_free(Packet* packet)
{
    buffer_free(packet->buf);
    free(packet->p_header);
    free(packet);
}