#include "aescipher.h"
#include "kex.h"
#include "rsa.h"
#include "common/putnum.h"
#include "log/ftplog.h"

void aes_key_setup(cipher_context* cipher_ctx)
{
    DH* dh;
    BIGNUM* shared_secret;

    dh = dh_creation();
    generate_kex_key(dh);
    compute_kex_key(dh, shared_secret, cipher_ctx->pub_key);

    BN_copy(cipher_ctx->key, shared_secret);
    cipher_ctx->key_len = BN_num_bits(cipher_ctx->key);
}

void aes_iv_setup(cipher_context* cipher_ctx)
{
    BIGNUM* iv;

    BN_rand(iv, AES_BLOCK_SIZE, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
    
    BN_copy(cipher_ctx->iv, iv);
    cipher_ctx->iv_len = BN_num_bits(cipher_ctx->iv);
}

int aes_cipher_init(cipher_context* cipher_ctx)
{
    aes_key_setup(cipher_ctx);
    aes_iv_setup(cipher_ctx);

    cipher_ctx->evp = EVP_CIPHER_CTX_new();
    cipher_ctx->evptype = EVP_aes_128_cbc();

}

int aes_cypher_encrypt( cipher_context* cipher_ctx, char* inbuf,
                        int inlen, char* outbuf, int outlen )
{
    unsigned char *convert_key, *convert_iv;
    BN_bn2bin(cipher_ctx->key, convert_key);
    BN_bn2bin(cipher_ctx->iv, convert_iv);

    if (!EVP_CipherInit_ex2(cipher_ctx->evp, cipher_ctx->evptype, 
                            (const char *) convert_key, (const char *) convert_iv, ENCRYPT, NULL))
    {
        LOG("Could not perform encryption\n");
        return 0;
    }

    if (!EVP_CipherUpdate(cipher_ctx->evp, outbuf, &outlen, inbuf, inlen))
    {
        LOG("Could not perform encryption\n");
        return 0;
    }

    return 1;
}

int aes_cypher_decrypt( cipher_context* cipher_ctx, char* inbuf,
                        int inlen, char* outbuf, int outlen )
{

    unsigned char *convert_key, *convert_iv;
    BN_bn2bin(cipher_ctx->key, convert_key);
    BN_bn2bin(cipher_ctx->iv, convert_iv);

    if (!EVP_CipherInit_ex2(cipher_ctx->evp, cipher_ctx->evptype, (const char *) convert_key, 
                            (const char *) convert_iv, DECRYPT, NULL))
    { 
        LOG("Could not perform encryption\n");
        return 0;
    }

    if (!EVP_CipherUpdate(cipher_ctx->evp, outbuf, &outlen, inbuf, inlen))
    {
        LOG("Could not perform encryption\n");
        return 0;
    }

    return 1;
}

