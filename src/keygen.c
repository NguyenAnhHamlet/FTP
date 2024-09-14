#include <stdio.h>
#include "secure/rsa.h"
#include "common/common.h"
#include "secure/secure.h"
#include "common/file.h"
#include <string.h>
#include "common/send.h"
#include "common/receive.h"
#include <time.h>
#include "keygen.h"

void keygen(int argc, ...)
{
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
}

int main(int argc, char* argvs[])
{
    keygen(argc,argvs);
    return 0;
}