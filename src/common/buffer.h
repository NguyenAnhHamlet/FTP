#ifndef __BUFFER__
#define __BUFFER__

#include <openssl/bn.h>
#include "putnum.h"

#define BUF_SIZE 4096

typedef struct {
	char   *buf;
	unsigned int offset;	
	unsigned int alloc;	
	unsigned int end;	
} Buffer;

void buffer_init(Buffer * buffer);

void buffer_free(Buffer * buffer);

void buffer_clear(Buffer * buffer);

void buffer_append(Buffer * buffer, const char *data, unsigned int len);

unsigned int buffer_len(Buffer * buffer);

void buffer_get(Buffer * buffer, char *buf, unsigned int len);

void buffer_put_bignum(Buffer * buffer, BIGNUM * value);

int buffer_get_bignum(Buffer * buffer, BIGNUM * value);

unsigned int buffer_get_int(Buffer * buffer);

void buffer_put_int(Buffer * buffer, unsigned int value);

#endif