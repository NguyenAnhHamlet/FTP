#ifndef __KEX_EXCHANGE__
#define __KEX_EXCHANGE__

#include <openssl/dh.h>

// Diffie–Hellman key exchange
// User ought to create a simple design which follow
// the basic principles of Diffie–Hellman key exchange

// 1. Both party agree to use the same value of G and P
// 2. Both party compute their own pubic values
// 3. Both party exchange public values
// 4. Both party compute the secret key using the received public value

/* rfc2409 "Second Oakley Group" (1024 bits) */
// create a simple DH object to stores public number P and G
// generate P and G public number

#ifdef OPENSSL_1
DH* dh_creation();
#elif OPENSSL_3 
// create a EVP_PKEY object and generate key pair at the same time
EVP_PKEY* EVP_PKEY_DH_init();
#endif

// first step in shared key computation: generate a public value. 
// Each party generate its own public value using the shared public 
// number P and G by the computation : G^<private_key> mod P
// private key will be generated randomly and stored in dh->priv_key
// public value that would be sent over to the other party and
// stored in dh->pub_key

#ifdef OPENSSL_1
int generate_keys(DH *dh);
#endif

// final step in computation : each party get the shared secret key 
// by doing the final computation : <pub_value>^<private_key> mod P
// It should be noticed that both party receive the public shared 
// value sent by the other party that they try to form a shared 
// secret key

#ifdef OPENSSL_1
int generate_secret_key(DH* dh, BIGNUM** shared_key, BIGNUM** pub_value);
#elif OPENSSL_3
int generate_secret_key(EVP_PKEY* pkey, BIGNUM** shared_key, BIGNUM** pub_value);
#endif

#endif