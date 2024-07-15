#ifndef __HMAC__
#define __HMAC__

#include <stdio.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <string.h>
#include <stdbool.h>

int HMACdecrypt(EVP_CIPHER_CTX *ctx, unsigned char *key, int key_len, 
                unsigned char *input, int input_len,
                unsigned char *output, int *output_len);
int HMACencrypt(EVP_CIPHER_CTX *ctx, unsigned char *key, int key_len, 
                unsigned char *input, int input_len,
                unsigned char *output, int *output_len);
int createSecretKey(unsigned char shared_key[16]);

#endif