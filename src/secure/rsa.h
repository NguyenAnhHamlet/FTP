#ifndef __RSA__
#define __RSA__

#include <stdio.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <string.h>
#include <stdbool.h>

#define public_RSAkey_file "/etc/RSApub.key"
#define private_RSAkey_file "/etc/RSAprivate.key"

#define KEY_SIZE 2048  

void generate_RSA_KEYPAIR(RSA * rsa);

void save_RSApublic_key(RSA * rsa, char path[]);

void save_RSAprivate_key(RSA * rsa, char path[]);

int sign_RSAChallenge( RSA * rsa, const unsigned char *challenge, 
                    int challenge_len, unsigned char *signature, 
                    size_t *signature_len);

int verify_RSAchallenge(RSA * rsa, const unsigned char *challenge, 
                    int challenge_len, const unsigned char *signature, 
                    size_t* signature_len);

int read_RSAauth_key(RSA * rsa, char path[], char* pattern);

int read_privateRSA_key(RSA * rsa, char path[]);

#endif