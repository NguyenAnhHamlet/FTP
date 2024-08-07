#ifndef __COMPRESS__
#define __COMPRESS__

#include "buffer.h"

void buffer_compress(Buffer* inbuf, Buffer* outbuf);
void buffer_uncompress(Buffer* inbuf, Buffer* outbuf);

#endif