#include <stdio.h>
#include "secure/rsa.h"
#include "common/common.h"
#include "secure/secure.h"
#include "common/file.h"
#include <string.h>
#include <time.h>
#include "secure/ed25519.h"

#define KEY_TYPE "-k"
#define OVEWRITE "-o"
#define ED25519_KEY "ed25519"
#define RSA_KEY "rsa"

// TODO: 
// Check the file existence before generating keys
// If there is no such file exist, try to touch one 

void ed25519_keygen()
{
    EVP_PKEY* pkey = NULL;
    generate_ed25519_key_pair(&pkey);
    save_ed25519_private_key(PRIVATE_ED25519, pkey);
    save_ed25519_public_key(PUBLIC_ED25519, pkey);
    EVP_PKEY_free(pkey);
}

void rsa_keygen()
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