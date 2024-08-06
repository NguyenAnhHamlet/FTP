#include "compress.h"
#include "zlib.h"

void compress(Buffer* inbuf, Buffer* outbuf)
{
    z_stream outgoing_stream;
    char buf[4096];
    int status;

    outgoing_stream.next_in = inbuf->buf + inbuf->offset;
    outgoing_stream.avail_in = buffer_len(inbuf);

    while(outgoing_stream.avail_out == 0)
    {
		outgoing_stream.next_out = buf;
		outgoing_stream.avail_out = sizeof(buf);

        status = deflate(&outgoing_stream, Z_PARTIAL_FLUSH);

        switch (status) 
        {
        case Z_OK:
			
			buffer_append(outbuf, buf,
				      sizeof(buf) - outgoing_stream.avail_out);
			break;
		case Z_STREAM_END:
			fatal("buffer_compress: deflate returned Z_STREAM_END");
		
		case Z_STREAM_ERROR:
			fatal("buffer_compress: deflate returned Z_STREAM_ERROR");
			
		case Z_BUF_ERROR:
			fatal("buffer_compress: deflate returned Z_BUF_ERROR");
			
		default:
			fatal("buffer_compress: deflate returned %d", status);
			
        }
    }
}

void uncompress(Buffer* inbuf, Buffer* outbuf)
{
    z_stream incoming_stream;
    char buf[4096];
	int status;

	incoming_stream.avail_in = buffer_len(inbuf);
	incoming_stream.next_in = buffer_ptr(inbuf);

	incoming_stream.next_out = buf;
	incoming_stream.avail_out = sizeof(buf);

    for (;;) {
		status = inflate(&incoming_stream, Z_PARTIAL_FLUSH);
		switch (status) {
		case Z_OK:
			buffer_append(outbuf, buf,
				      sizeof(buf) - incoming_stream.avail_out);
			incoming_stream.next_out = buf;
			incoming_stream.avail_out = sizeof(buf);
			break;
		case Z_STREAM_END:
			fatal("buffer_uncompress: inflate returned Z_STREAM_END");
			
		case Z_DATA_ERROR:
			fatal("buffer_uncompress: inflate returned Z_DATA_ERROR");
			
		case Z_STREAM_ERROR:
			fatal("buffer_uncompress: inflate returned Z_STREAM_ERROR");
			
		case Z_BUF_ERROR:
			
			return;
		case Z_MEM_ERROR:
			fatal("buffer_uncompress: inflate returned Z_MEM_ERROR");
			
		default:
			fatal("buffer_uncompress: inflate returned %d", status);
		}
	}
}