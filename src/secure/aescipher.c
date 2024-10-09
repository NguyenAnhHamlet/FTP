#include "aescipher.h"
#include "kex.h"
#include "rsa.h"
#include "common/putnum.h"
#include "log/ftplog.h"

int aes_cipher_init(cipher_context* cipher_ctx)
{
    if(!cipher_ctx)
    {
        cipher_ctx = (cipher_context* ) malloc(sizeof(cipher_context)); 
    }

    if(!cipher_ctx->evp || !cipher_ctx->evptype )
    {
        cipher_ctx->evp = EVP_CIPHER_CTX_new();
        cipher_ctx->evptype = EVP_aes_128_cbc();
    }

    cipher_ctx->key = BN_new();

    return 1;
}

int aes_cipher_reinit(cipher_context* ctx)
{
    ctx->evp = EVP_CIPHER_CTX_new();
    ctx->evptype = EVP_aes_128_cbc();

    return 1;
}

int aes_cypher_encrypt( cipher_context* cipher_ctx, char* inbuf,
                        int inlen, char* outbuf, int outlen )
{
    unsigned char *convert_key;
    BN_bn2bin(cipher_ctx->key, convert_key);

    if (!EVP_CipherInit_ex2(cipher_ctx->evp, cipher_ctx->evptype, 
                            (const char *) convert_key, NULL, ENCRYPT, NULL))
    {
        LOG(SERVER_LOG, "Could not perform encryption\n");
        LOG(CLIENT_LOG, "Could not perform encryption\n");
        return 0;
    }

    if (!EVP_CipherUpdate(cipher_ctx->evp, outbuf, &outlen, inbuf, inlen))
    {
        LOG(SERVER_LOG, "Could not perform encryption\n");
        LOG(CLIENT_LOG, "Could not perform encryption\n");
        return 0;
    }

    return 1;
}

int aes_cypher_decrypt( cipher_context* cipher_ctx, char* inbuf,
                        int inlen, char* outbuf, int outlen )
{

    unsigned char *convert_key;
    BN_bn2bin(cipher_ctx->key, convert_key);

    if (!EVP_CipherInit_ex2(cipher_ctx->evp, cipher_ctx->evptype, (const char *) convert_key, 
                            NULL, DECRYPT, NULL))
    { 
        LOG(SERVER_LOG, "Could not perform encryption\n");
        LOG(CLIENT_LOG, "Could not perform encryption\n");
        return 0;
    }

    if (!EVP_CipherUpdate(cipher_ctx->evp, outbuf, &outlen, inbuf, inlen))
    {
        LOG(SERVER_LOG, "Could not perform encryption\n");
        LOG(CLIENT_LOG, "Could not perform encryption\n");
        return 0;
    }

    return 1;
}

