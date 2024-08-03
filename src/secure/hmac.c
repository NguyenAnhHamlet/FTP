#include "hmac.h"
#include "common/common.h"

int HMACdecrypt(EVP_CIPHER_CTX *ctx, unsigned char *key, int key_len,
                unsigned char *input, int input_len,
                unsigned char *output, int *output_len)
{
    if (!ctx) fatal("ctx is NULL\n");
    int ciphertext_len;
    int final_len;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, NULL) != 1)
        fatal("Error initializing decryption\n");
    
    unsigned char iv[EVP_CIPHER_iv_length(EVP_aes_256_cbc())];
    memset(iv, 0, sizeof(iv));

    if (EVP_CipherUpdate(ctx, output, &ciphertext_len, input, input_len) != 1)
        fatal("Error updating decryption context\n");

    *output_len = ciphertext_len + final_len;

    return Success;
}

int HMACencrypt(EVP_CIPHER_CTX *ctx, unsigned char *key, int key_len,
                unsigned char *input, int input_len,
                unsigned char *output, int *output_len)
{
    if (!ctx) fatal("ctx is NULL\n");
    int ciphertext_len;
    int final_len;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, NULL) != 1)
        fatal("Error initializing decryption\n");
    
    unsigned char iv[EVP_CIPHER_iv_length(EVP_aes_256_cbc())];
    memset(iv, 0, sizeof(iv));

    if (EVP_CipherUpdate(ctx, output, &ciphertext_len, input, input_len) != 1)
        fatal("Error updating decryption context\n");

    *output_len = ciphertext_len + final_len;

    return Success;
}

int createSecretKey(unsigned char shared_key[16])
{
    if (RAND_bytes(shared_key, sizeof(shared_key)) != 1)
        fatal("Could not create secret key");

    return Success;
}