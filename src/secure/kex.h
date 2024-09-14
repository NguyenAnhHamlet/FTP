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
DH* dh_creation();

// first step in shared key computation: generate a public value. 
// Each party generate its own public value using the shared public 
// number P and G by the computation : G^<private_key> mod P
// private key will be generated randomly and stored in dh->priv_key
// public value that would be sended over to the other party would 
// be stored in dh->pub_key
int generate_pub_keys(DH *dh);

// final step in computation : each party get the shared secret key 
// by doing the final computation : <pub_value>^<private_key> mod P
// It should be noticed that both party receive the public shared 
// value sended by the other party that they try to form a shared 
// secret key
int generate_secret_key(DH* dh, BIGNUM* shared_key, BIGNUM* pub_value);

#endif