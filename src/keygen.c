#include <stdio.h>
#include "secure/rsa.h"
#include "common/common.h"
#include "secure/secure.h"
#include "common/file.h"
#include <string.h>
#include <time.h>
#include "secure/ed25519.h"
#include "common/file.h"

#define KEY_TYPE "-k"
#define OVEWRITE "-o"
#define ED25519_KEY "ed25519"
#define RSA_KEY "rsa"

void ed25519_keygen()
{
    // check and touch 
    if(not_exist(PUBLIC_ED25519) || not_exist(PRIVATE_ED25519))
    {
        if( !create_file(PUBLIC_ED25519) || 
            !create_file(PRIVATE_ED25519))
        {
            perror("Fail to create file with error: ");
            return;
        }

        CHMOD_640(PUBLIC_ED25519);
        CHMOD_640(PRIVATE_ED25519);
    }

    EVP_PKEY* pkey = NULL;
    generate_ed25519_key_pair(&pkey);
    save_ed25519_private_key(PRIVATE_ED25519, pkey);
    save_ed25519_public_key(PUBLIC_ED25519, pkey);
    EVP_PKEY_free(pkey);
}

void rsa_keygen()
{
    // check and touch 
    if(not_exist(PUBLIC_RSA) || not_exist(PRIVATE_RSA))
    {
        if( !create_file(PUBLIC_RSA) || 
            !create_file(PRIVATE_RSA))
        {
            perror("Fail to create file with error: ");
            return;
        }

        CHMOD_640(PUBLIC_RSA);
        CHMOD_640(PRIVATE_RSA);
    }

#ifdef OPENSSL_1
    RSA* rsa = RSA_new();
    if (!rsa) 
    {
        RSA_free(rsa);
        fatal("Could not initialize object rsa\n");
    }

    generate_RSA_KEYPAIR(rsa);
    save_RSApublic_key(rsa, PUBLIC_RSA);
    save_RSAprivate_key(rsa, PRIVATE_RSA);
    RSA_free(rsa);

#elif OPENSSL_3
    EVP_PKEY *pkey = NULL;

    generate_rsa_key_pair(&pkey);
    save_rsa_public_key(PUBLIC_RSA, pkey);
    save_rsa_private_key(PRIVATE_RSA, pkey);
    EVP_PKEY_free(pkey);
#endif
}

void keygen(const char* key)
{
    if(!strncmp(key, ED25519_KEY, strlen(key)))
        ed25519_keygen();
    else if(strncmp(key, RSA_KEY, strlen(key)))
        rsa_keygen();
    else 
    {
        rsa_keygen();
        ed25519_keygen();
    }
    
}

int main(int argc, char* argvs[])
{
    int i =0;
    while(i < argc)
    {
        if(!strncmp(argvs[i], KEY_TYPE, 2))
        {
            i++;
            keygen(argvs[i]);
            return 0;
        }
        i++;
    }

    rsa_keygen();
    ed25519_keygen();

    return 0;
}