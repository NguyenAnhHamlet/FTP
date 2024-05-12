#include <stdio.h>
#include "edcsa.h"
#include "hmac.h"
#include "rsa.h"
#include "common.h"
#include "secure.h"
#include "file.h"
#include <string.h>
#include "send.h"
#include "receive.h"
#include <time.h>
#include "keygen.h"

void keygen(int argc, ...)
{
    va_list ptr;

    va_start(ptr, argc);

    for(int i =0; i< argc ; ++i)
    {
        char* arg = va_arg(ptr, char*);
        EDCSA_key_pair* ECDSA;
        RSA* rsa;

        if(strcmp(arg, KEY_TYPE))
        {
            char* arg = va_arg(ptr, char*);

            if(!strcmp(arg, ECDSA_KEY))
            {
                generate_ECDSA_KEYPAIR(ECDSA);
            }
            else if(!strcmp(arg, RSA_KEY))
            {
                generate_RSA_KEYPAIR(rsa);
            }
            else
            {
                va_end(ptr);
                errorLog("There is no such key\n");
            }
        }
        else if(!strcmp(arg, OVEWRITE))
        {
            if(ECDSA) 
            {
                save_public_key(ECDSA,public_ECDSAkey_file);
                save_private_key(ECDSA, private_ECDSAkey_file);
            }
            else if(rsa)
            {
                save_RSAprivate_key(rsa,private_RSAkey_file);
                save_RSApublic_key(rsa, public_RSAkey_file);
            }
        }
        else
        {
            va_end(ptr);
            errorLog("There is no such type of argument\n");
        }
    }
    
    va_end(ptr);
}

int main(int argc, char* argvs[])
{
    keygen(argc,argvs);
    return 0;
}