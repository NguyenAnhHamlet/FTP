#ifndef __COMPRESS__
#define __COMPRESS__

#include "buffer.h"

void compress(Buffer* inbuf, Buffer* outbuf);
void uncompress(Buffer* inbuf, Buffer* outbuf);

#endif