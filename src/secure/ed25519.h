#ifndef __ED25519__

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define PUBLIC_ED25519 "/etc/ftp/ed25519.pub"
#define PRIVATE_ED25519 "/etc/ftp/ed25519.priv"

#define CHALLENGE_LEN 32 

void generate_ed25519_key_pair(EVP_PKEY **pkey);
void save_ed25519_public_key(char path[], EVP_PKEY *pkey);
void save_ed25519_private_key(char path[], EVP_PKEY *pkey);
int ed25519_priv_sign(EVP_PKEY* pkey, BIGNUM** inbn, BIGNUM** outbn);
int ed25519_pub_verify(EVP_PKEY* pkey, BIGNUM** inbn, BIGNUM** outbn);
int load_ed25519_auth_key(EVP_PKEY **pkey, char path[]);
int load_private_ed25519_key(EVP_PKEY **pkey, char path[]);

#define __ED25519__
#endif