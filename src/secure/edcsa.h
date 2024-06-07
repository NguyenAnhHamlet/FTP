#ifndef __EDCSA__
#define __EDCSA__

#include <stdio.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <string.h>
#include <stdbool.h>

#define public_ECDSAkey_file "/etc/pub/ECDSApub.key"
#define private_ECDSAkey_file "/etc/priv/ECDSAprivate.key"

#define CURVE_NAME "secp256k1"

typedef struct EDCSA_key_pair
{
    EC_GROUP* ecgroup;
    EC_KEY *eckey;
} EDCSA_key_pair;

void set_EDCSA_key_pair(EDCSA_key_pair* ECDSA, EC_GROUP* ecgroup,
                        EC_KEY *eckey);

void generate_ECDSA_KEYPAIR(EDCSA_key_pair* ECDSA);

void save_public_key(EDCSA_key_pair* ECDSA, char path[]);

void save_private_key(EDCSA_key_pair* ECDSA, char path[]);

int sign_Challenge( EDCSA_key_pair* ECDSA, BIGNUM *challenge, 
                    int challenge_len, BIGNUM *signature, 
                    size_t *signature_len);

int ecdsa_priv_decrypt(EDCSA_key_pair* ECDSA, BIGNUM *challenge, 
                    int challenge_len, BIGNUM *signature, 
                    size_t* signature_len);

int read_auth_key(EDCSA_key_pair* ECDSA, char path[], char* pattern);

int read_private_key(EDCSA_key_pair* ECDSA, char path[]);

#endif

