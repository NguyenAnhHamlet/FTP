#ifndef __KEX_EXCHANGE__
#define __KEX_EXCHANGE__

#include <openssl/dh.h>

/* rfc2409 "Second Oakley Group" (1024 bits) */
DH* dh_creation();
int generate_kex_key(DH *dh);
int compute_kex_key(DH* dh, BIGNUM* shared_secret, BIGNUM* pub_key);

#endif