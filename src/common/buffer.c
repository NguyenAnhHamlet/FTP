#include "buffer.h"
#include <string.h>
#include "common/common.h"

void buffer_init(Buffer * buffer)
{
    buffer->alloc = 4096;
	buffer->offset = 0;
	buffer->buf = (char*) malloc(buffer->alloc);
	buffer->end = 0;
}

void buffer_free(Buffer * buffer)
{
    memset(buffer->buf, 0, buffer->alloc);
	free(buffer->buf);
}

void buffer_clear(Buffer * buffer)
{
	buffer->offset = 0;
	buffer->end = 0;
}

void buffer_append_str(Buffer * buffer, const char *data, unsigned int len)
{
	if (buffer->offset == buffer->end) 
	{
		buffer->offset = 0;
		buffer->end = 0;
	}

restart:
	// enough space for data -> write in buffer
    if (buffer->end + len < buffer->alloc)
    {
        memcpy(buffer->buf + buffer->end, data, len);
        return;
    }

	// There is not enough space for data
    // Increase the size of buffer and 
    // retry the append operation
   
    buffer->alloc += (len + BUF_SIZE);
    char *new_point = realloc(buffer->buf, buffer->alloc);

    if(!new_point) 
        fatal("xrealloc: out of memory (new_size %d bytes)", (int) buffer->alloc);
    
    buffer->buf  = new_point;
    goto restart;
    
}

void buffer_get_data(Buffer* buffer, char* data, unsigned int* len)
{
	data = buffer->buf + buffer->offset;
	*len = buffer->end - buffer->offset;
}

unsigned int buffer_len(Buffer * buffer)
{
    return buffer->end - buffer->offset;
}

void buffer_get(Buffer * buffer, char *buf, unsigned int len)
{   
    if (len > buffer->end - buffer->offset)
		fatal("buffer_get trying to get more bytes than in buffer");
	memcpy(buf, buffer->buf + buffer->offset, len);
	buffer->offset += len;
}

void
buffer_put_bignum(Buffer *buffer, BIGNUM *value)
{
	int bits = BN_num_bits(value);
	int bin_size = (bits + 7) / 8;
	char *buf = (char*)malloc(bin_size);
	int oi;
	char msg[2];

	// Get the value of in binary 
	oi = BN_bn2bin(value, buf);
	if (oi != bin_size)
		fatal("buffer_put_bignum: BN_bn2bin() failed: oi %d != bin_size %d",
		      oi, bin_size);

	/* Store the number of bits in the buffer in two bytes, msb first. */
	PUT_16BIT(msg, bits);
	buffer_append_str(buffer, msg, 2);
	/* Store the binary data. */
	buffer_append_str(buffer, buf, oi);

	memset(buf, 0, bin_size);
	free(buf);
}

int
buffer_get_bignum(Buffer *buffer, BIGNUM *value)
{
	int bits, bytes;
	unsigned char buf[2], *bin;

	/* Get the number for bits. */
	buffer_get(buffer, (char *) buf, 2);
	bits = GET_16BIT(buf);
	/* Compute the number of binary bytes that follow. */
	bytes = (bits + 7) / 8;
	if (buffer_len(buffer) < bytes)
		fatal("buffer_get_bignum: input buffer too small");
	bin = buffer->buf + buffer->offset;
	BN_bin2bn(bin, bytes, value);
	buffer->buf += bytes;

	if(BN_num_bits(value) != bits)
		return -1;

	return 2 + bytes;
}

unsigned int 
buffer_get_int(Buffer *buffer)
{
	unsigned char buf[4];
	buffer_get(buffer, (char *) buf, 4);
	return GET_32BIT(buf);
}

void 
buffer_put_int(Buffer *buffer, unsigned int value)
{
	char buf[4];
	PUT_32BIT(buf, value);
	buffer_append_str(buffer, buf, 4);
}
