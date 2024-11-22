#include <stdio.h>
#include "secure/rsa.h"
#include "common/common.h"
#include "secure/secure.h"
#include "common/file.h"
#include <string.h>
#include <time.h>
#include "keygen.h"

void keygen(int argc, ...)
{

#ifdef OPENSSL_1
    RSA* rsa = RSA_new();
    if (!rsa) 
    {
        RSA_free(rsa);
        fatal("Could not initialize object rsa\n");
    }

    generate_RSA_KEYPAIR(rsa);
    save_RSApublic_key(rsa, public_RSAkey_file);
    save_RSAprivate_key(rsa,private_RSAkey_file);
    RSA_free(rsa);

#elif OPENSSL_3
    EVP_PKEY *pkey = NULL;

    generate_rsa_key_pair(&pkey);
    save_rsa_public_key(public_RSAkey_file, pkey);
    save_rsa_private_key(private_RSAkey_file, pkey);
    EVP_PKEY_free(pkey);
#endif

}

int main(int argc, char* argvs[])
{
    keygen(argc,argvs);
    return 0;
}