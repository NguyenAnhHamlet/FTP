#include "aescipher.h"
#include "kex.h"
#include "rsa.h"
#include "common/putnum.h"
#include "log/ftplog.h"

int aes_cipher_init(cipher_context* cipher_ctx)
{
    cipher_ctx->evp = EVP_CIPHER_CTX_new();
    cipher_ctx->evptype = EVP_aes_256_cbc();
    cipher_ctx->key = BN_new();

    return 1;
}

int aes_cipher_reinit(cipher_context* ctx)
{
    ctx->evp = EVP_CIPHER_CTX_new();
    ctx->evptype = EVP_aes_256_cbc();

    return 1;
}

int aes_cypher_encrypt( cipher_context* cipher_ctx, char* inbuf,
                        int inlen, char* outbuf, int* outlen )
{
    unsigned char *convert_key;
    int tmplen;

    int bits = BN_num_bits(cipher_ctx->key);
	int bin_size = (bits + 7) / 8;
    convert_key = (unsigned char*)malloc(bin_size);
    memset(convert_key, 0, bin_size);
    BN_bn2bin(cipher_ctx->key, convert_key);
    EVP_CIPHER_CTX_reset(cipher_ctx->evp);

    if (!EVP_CipherInit_ex2(cipher_ctx->evp, EVP_aes_256_cbc(), 
                           (const char *) convert_key, NULL, ENCRYPT,
                           NULL))
    {
        unsigned long err_code = ERR_get_error();

        if (err_code) 
        {
            char err_buf[128];
            ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
            LOG(SERVER_LOG, "Could not perform encryption %s\n", err_buf);
        }

        LOG(SERVER_LOG, "Could not perform encryption\n");
        return 0;
    }

    if (!EVP_CipherUpdate(cipher_ctx->evp, outbuf, outlen, inbuf, inlen))
    {
        unsigned long err_code = ERR_get_error();

        if (err_code) 
        {
            char err_buf[128];
            ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
            LOG(SERVER_LOG, "Could not perform encryption %s\n", err_buf);
        }

        LOG(SERVER_LOG, "Could not perform encryption\n");
        return 0;
    }

    if (!EVP_EncryptFinal_ex(cipher_ctx->evp, outbuf + *outlen, &tmplen)) 
    {
        unsigned long err_code = ERR_get_error();

        if (err_code) 
        {
            char err_buf[128];
            ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
            LOG(SERVER_LOG, "Could not perform encryption %s\n", err_buf);
        }

        LOG(SERVER_LOG, "Could not perform decryption\n");
        EVP_CIPHER_CTX_free(cipher_ctx->evp);
        return 0;
    }

    *outlen += tmplen;

    return 1;
}

int aes_cypher_decrypt( cipher_context* cipher_ctx, char* inbuf,
                        int inlen, char* outbuf, int* outlen )
{
    unsigned char *convert_key;
    int tmplen;

    int bits = BN_num_bits(cipher_ctx->key);
	int bin_size = (bits + 7) / 8;
    convert_key = (unsigned char*)malloc(bin_size);
    memset(convert_key, 0, bin_size);
    BN_bn2bin(cipher_ctx->key, convert_key);
    EVP_CIPHER_CTX_reset(cipher_ctx->evp);

    if (!EVP_CipherInit_ex2(cipher_ctx->evp, EVP_aes_256_cbc(), 
                            (const char *) convert_key, 
                            NULL, DECRYPT, NULL))
    { 
        unsigned long err_code = ERR_get_error();

        if (err_code) 
        {
            char err_buf[128];
            ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
            LOG(SERVER_LOG, "Could not perform decryption %s\n", err_buf);
        }
        return 0;
    }

    if (!EVP_CipherUpdate(cipher_ctx->evp, outbuf, outlen, inbuf, inlen))
    {
        unsigned long err_code = ERR_get_error();

        if (err_code) 
        {
            char err_buf[128];
            ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
            LOG(SERVER_LOG, "Could not perform decryption %s\n", err_buf);
        }

        LOG(SERVER_LOG, "Could not perform decryption\n");
        return 0;
    }

    if (!EVP_DecryptFinal_ex(cipher_ctx->evp, outbuf + *outlen, &tmplen)) 
    {
        unsigned long err_code = ERR_get_error();

        if (err_code) 
        {
            char err_buf[128];
            ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
            LOG(SERVER_LOG, "Could not perform decryption %s\n", err_buf);
        }

        LOG(SERVER_LOG, "Could not perform decryption\n");
        EVP_CIPHER_CTX_free(cipher_ctx->evp);
        return 0;
    }

    *outlen += tmplen;

    return 1;
}

