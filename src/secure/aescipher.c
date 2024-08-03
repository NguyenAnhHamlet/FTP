#include "aescipher.h"
#include "kex.h"
#include "rsa.h"
#include "common/putnum.h"

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

    BN_rand(iv, AES_BLOCK_SIZE, NULL, NULL);
    
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
    if (!EVP_CipherInit_ex2(cipher_ctx->evp, cipher_ctx->evptype, cipher_ctx->key, 
        cipher_ctx->iv, ENCRYPT, NULL))
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
    if (!EVP_CipherInit_ex2(cipher_ctx->evp, cipher_ctx->evptype, cipher_ctx->key, 
    cipher_ctx->iv, DECRYPT, NULL))
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

