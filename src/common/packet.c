#include "packet.h"
#include <unistd.h>
#include <arpa/inet.h>
#include "compress.h"
#include <fcntl.h>
#include <errno.h>
#include "common/common.h"
#include <sys/select.h>
#include "common/buffer.h"
#include <errno.h> 
#include <stdio.h> 
#include <fcntl.h>
#include "log/ftplog.h"

void packet_init(Packet* packet, unsigned int out_port, unsigned int packet_type,
                 unsigned int in_port )
{
    packet->buf = (Buffer*) malloc(sizeof(Buffer));
    packet->p_header = (packet_header*) malloc(sizeof(packet_header));
    buffer_init(packet->buf);
    packet_set_port(packet, in_port, out_port);
    packet->p_header->compression_mode = 0;
}

void packet_set_port(Packet* packet, unsigned int in_port, unsigned int out_port)
{
    packet->in_port = in_port;
    packet->out_port = out_port;
}

void packet_set_nonblocking(Packet* packet)
{
    if (fcntl(packet->in_port, F_SETFL, O_NONBLOCK) < 0)
		perror("fcntl O_NONBLOCK");

	if (packet->out_port != packet->in_port) 
    {
		if (fcntl(packet->out_port, F_SETFL, O_NONBLOCK) < 0)
			perror("fcntl O_NONBLOCK:");
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

    if(buffer_len(packet->buf) > 0)
    {
        buffer_get_data(packet->buf, buf, &len);
        len = write(packet->out_port, buf, BUF_LEN); 

        if(len <= 0)
        {
            if (errno == EAGAIN)
				return;
            else
                fatal("Write failed: %.100s", strerror(errno));
        }

        buffer_consume(packet->buf, len);
    }
}

void set_packet_compress(Packet* packet)
{
    packet->p_header->compression_mode = 1;
}

void unset_packet_compress(Packet* packet)
{
    packet->p_header->compression_mode = 0;
}

int packet_read(Packet* packet)
{
    int len =0;
    int curr_len = 0;
    fd_set set;
    char buf[BUF_LEN];

    packet_read_header(packet);

    if(packet->p_header->compression_mode)
    {
        Buffer* outbuf;
        buffer_uncompress(packet->buf, outbuf );
        buffer_clear(packet->buf);
        buffer_append_str(packet->buf, buffer_get_ptr(outbuf), buffer_len(outbuf));
    }
    
    while(  len < packet->p_header->tt_len && 
            curr_len = read(packet->in_port, buf, BUF_LEN ) > 0)
    {
        buffer_append_str(packet->buf, buf, curr_len);
        len += curr_len;
    }

    return 1;
}

// Ought to read the header in this primitive manner
// The total len of the packet needed to be got first 
// to make sure the receiving endpoint get enough 
// data from the sending endpoint
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
        if(read(packet->in_port, interger, 4, 0) < 0)
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

    packet_set_header(packet, identification, tt_len, 
                      fragment_offset, packet_type, 
                      compression_mode);

    return 1;
}

int packet_send_wait(Packet* packet)
{
    if(packet->p_header->compression_mode == 1)
    {
        Buffer* outbuf = (Buffer*) malloc(sizeof(Buffer)) ;
        buffer_init(outbuf);
        buffer_compress(packet->buf, outbuf );
        buffer_clear(packet->buf);
        buffer_append_str(packet->buf, buffer_get_ptr(outbuf), buffer_len(outbuf));
    }

    int curr_len = 0;
    fd_set write_set;
    struct timeval timeout;
    int retval;

    timeout.tv_sec = 0;
    timeout.tv_usec = 1000000 ;

    while(buffer_len(packet->buf) > 0)
    {
		FD_ZERO(&write_set);
		FD_SET(packet->out_port, &write_set);
		retval = select(packet->out_port + 1, NULL, &write_set, NULL, &timeout);

        if(retval <= 0)
        {
            perror("Select failure\n");
        }

        LOG(SERVER_LOG, "RUNNING HERE\n");

        packet_send(packet);
    }
}

int packet_wait(Packet* packet)
{
    fd_set read_set;

    FD_ZERO(&read_set);
	FD_SET(packet->in_port, &read_set);

    int res = select(packet->in_port + 1, &read_set, NULL, NULL, &packet->time_out);

    return res;
}

int packet_read_expect(Packet* packet, unsigned int expect_value)
{
    int packet_type;
    int res;
    
    res = packet_wait(packet);

    if(res == 0)
    {
        LOG(SERVER_LOG,"Time out receiving packet\n");
        LOG(CLIENT_LOG,"Time out receiving packet\n");
        return 0;       
    }

    if(res < 0)
    {
        LOG(SERVER_LOG, "Error in select function\n");
        LOG(CLIENT_LOG, "Error in select function\n");
        return -1;
    }

    packet_read(packet);
    packet_type = packet->p_header->packet_type;

    return packet_type == expect_value ? 1 : 0;      
}

int packet_append_str(char* str, Packet* packet, unsigned int len)
{
    buffer_append_str(packet->buf, str, len);

    return 1;
}

int packet_append_bignum(BIGNUM* bignum, Packet* packet)
{
    buffer_put_bignum(packet->buf, bignum);

    return 1;
}

int packet_append_int(int num, Packet* packet)
{
    buffer_put_int(packet->buf, num);

    return 1;
}

unsigned int packet_get_int(Packet* packet)
{
    return buffer_get_int(packet->buf );
}

int packet_get_str(Packet* packet, char* str, unsigned int* len)
{
    buffer_get_data(packet->buf, str, len);

    return 1;
}

int packet_get_bignum(BIGNUM* bignum, Packet* packet)
{
    return buffer_get_bignum(packet->buf, bignum);
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
                        int tt_len, int fragment_offset,
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