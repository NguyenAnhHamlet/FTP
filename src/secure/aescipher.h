#ifndef __CIPHER__
#define __CIPHER__

#include <openssl/evp.h>

#define AES_BLOCK_SIZE 16 

typedef struct 
{
    EVP_CIPHER_CTX* evp;
    const EVP_CIPHER* evptype;

    int encrypt;

    BIGNUM* key;

    unsigned int key_len;
    unsigned int iv_len;

} cipher_context;

typedef enum 
{
    DECRYPT = 0,
    ENCRYPT = 1
} enc_dec;

int aes_cipher_init(cipher_context* cipher_ctx);
int aes_cipher_reinit(cipher_context* ctx);
int aes_cypher_encrypt( cipher_context* cipher_ctx, char* inbuf,
                        int inlen, char* outbuf, int outlen );
int aes_cypher_decrypt( cipher_context* cipher_ctx, char* inbuf, 
                        int inlen, char* outbuf, int outlen);

#endif