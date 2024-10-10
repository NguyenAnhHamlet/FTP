#ifndef __RSA__
#define __RSA__

#include <stdio.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/bio.h> 
#include <string.h>
#include <stdbool.h>

#define public_RSAkey_file "/etc/pub/RSApub.key"
#define private_RSAkey_file "/etc/priv/RSAprivate.key"

#define KEY_SIZE 128  

void generate_RSA_KEYPAIR(RSA *key_pair);

void save_RSApublic_key(RSA * rsa, char path[]);

void save_RSAprivate_key(RSA * rsa, char path[]);

int rsa_pub_encrypt(RSA * pub, BIGNUM** in, BIGNUM** out);

int rsa_pub_decrypt(RSA * pub, BIGNUM** in, BIGNUM** out);

int load_rsa_auth_key(RSA **pub_key, char path[]);

int load_private_rsa_key(RSA **private_key, char path[]);

void rsa_read_public_key(char path[], char* key);

void rsa_read_private_key(char path[], char* key);

#endif