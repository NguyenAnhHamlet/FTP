#include "compress.h"
#include <zlib.h>
#include "common/common.h"

void buffer_compress(Buffer* inbuf, Buffer* outbuf)
{
    z_stream outgoing_stream;
    char buf[inbuf->alloc];
    int status;

	memset(&outgoing_stream, 0, sizeof(outgoing_stream));
	status = deflateInit(&outgoing_stream, Z_DEFAULT_COMPRESSION);

    outgoing_stream.next_in = buffer_get_ptr(inbuf);
    outgoing_stream.avail_in = buffer_len(inbuf);

    while(outgoing_stream.avail_out == 0)
    {
		outgoing_stream.next_out = buf;
		outgoing_stream.avail_out = sizeof(buf);

        status = deflate(&outgoing_stream, Z_PARTIAL_FLUSH);

        switch (status) 
        {
        case Z_OK:
			
			buffer_append_str(outbuf, buf, 
						  	  sizeof(buf) - outgoing_stream.avail_out);
			break;
		case Z_STREAM_END:
			deflateEnd(&outgoing_stream);
			fatal("buffer_compress: deflate returned Z_STREAM_END");
		
		case Z_STREAM_ERROR:
			deflateEnd(&outgoing_stream);
			fatal("buffer_compress: deflate returned Z_STREAM_ERROR");
			
		case Z_BUF_ERROR:
			deflateEnd(&outgoing_stream);
			fatal("buffer_compress: deflate returned Z_BUF_ERROR");
			
		default:
			deflateEnd(&outgoing_stream);
			fatal("buffer_compress: deflate returned %d", status);
			
        }
    }

	deflateEnd(&outgoing_stream);
}

void buffer_uncompress(Buffer* inbuf, Buffer* outbuf)
{
    z_stream incoming_stream;
    char buf[inbuf->alloc];
	int status;

	memset(&incoming_stream, 0, sizeof(incoming_stream));
	status = inflateInit(&incoming_stream);

	incoming_stream.avail_in = buffer_len(inbuf);
	incoming_stream.next_in = buffer_get_ptr(inbuf);

	incoming_stream.next_out = buf;
	incoming_stream.avail_out = sizeof(buf);

    for (;;) 
	{
		status = inflate(&incoming_stream, Z_PARTIAL_FLUSH);
		switch (status) {
		case Z_OK:
			buffer_append_str(outbuf, buf,
				      		  sizeof(buf) - incoming_stream.avail_out);
			incoming_stream.next_out = buf;
			incoming_stream.avail_out = sizeof(buf);
			break;
		case Z_STREAM_END:
			inflateEnd(&incoming_stream);
			fatal("buffer_uncompress: inflate returned Z_STREAM_END");
			
		case Z_DATA_ERROR:
			inflateEnd(&incoming_stream);
			fatal("buffer_uncompress: inflate returned Z_DATA_ERROR");
			
		case Z_STREAM_ERROR:
			inflateEnd(&incoming_stream);
			fatal("buffer_uncompress: inflate returned Z_STREAM_ERROR");
			
		case Z_BUF_ERROR:
			inflateEnd(&incoming_stream);
			return;

		case Z_MEM_ERROR:
			inflateEnd(&incoming_stream);
			fatal("buffer_uncompress: inflate returned Z_MEM_ERROR");
			
		default:
			inflateEnd(&incoming_stream);
			fatal("buffer_uncompress: inflate returned %d", status);
		}
	}

	inflateEnd(&incoming_stream);
}