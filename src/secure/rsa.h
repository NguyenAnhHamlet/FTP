#ifndef __RSA__
#define __RSA__

#include <stdio.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/bio.h> 
#include <string.h>
#include <stdbool.h>

#define PUBLIC_RSA "/etc/ftp/rsa.pub"
#define PRIVATE_RSA "/etc/ftp/rsa.priv"

#define KEY_SIZE 2056  

#ifdef OPENSSL_3
void generate_rsa_key_pair(EVP_PKEY **pkey);
void save_rsa_public_key(char path[], EVP_PKEY *pkey);
void save_rsa_private_key(char path[], EVP_PKEY *pkey);
int rsa_pub_encrypt(EVP_PKEY* pkey, BIGNUM** inbn, BIGNUM** outbn);
int rsa_pub_decrypt(EVP_PKEY* pkey, BIGNUM** inbn, BIGNUM** outbn);
int load_rsa_auth_key(EVP_PKEY **pkey, char path[]);
int load_private_rsa_key(EVP_PKEY **pkey, char path[]);
void rsa_pubkey_hash(EVP_PKEY* pub_key, char** ret, int* retlen);

#elif OPENSSL_1
void generate_RSA_KEYPAIR(RSA *key_pair);
void save_RSApublic_key(RSA * rsa, char path[]);
void save_RSAprivate_key(RSA * rsa, char path[]);
int rsa_pub_encrypt(RSA * pub, BIGNUM** in, BIGNUM** out);
int rsa_pub_decrypt(RSA * pub, BIGNUM** in, BIGNUM** out);
int load_rsa_auth_key(RSA **pub_key, char path[]);
int load_private_rsa_key(RSA **private_key, char path[]);
void rsa_pubkey_hash(RSA* pubkey, char** ret, int* retlen);
#endif



#endif