#include "edcsa.h"
#include "file.h"
#include <string.h>
#include "common.h"

void set_EDCSA_key_pair(EDCSA_key_pair* ECDSA, EC_GROUP* ecgroup,
                        EC_KEY *eckey)
{
    ECDSA->ecgroup = ecgroup;
    ECDSA->eckey = eckey;
}

void generate_ECDSA_KEYPAIR(EDCSA_key_pair* ECDSA)
{
    // Set EC group for the key
    if (EC_KEY_set_group(ECDSA->eckey, ECDSA->ecgroup) != 1) 
    {
        ERR_print_errors_fp(stderr);
        EC_GROUP_free(ECDSA->ecgroup);
        EC_KEY_free(ECDSA->eckey);
        return ;
    }

    // Generate key pair
    if (!EC_KEY_generate_key(ECDSA->eckey)) 
    {
        ERR_print_errors_fp(stderr);
        EC_GROUP_free(ECDSA->ecgroup);
        EC_KEY_free(ECDSA->eckey);
        return ;
    }


}

void save_public_key(EDCSA_key_pair* ECDSA, char path[])
{
    EVP_PKEY *keypair = EVP_PKEY_new();

    if(!keypair) errorLog("Couldn't create keypair");

    if(!EVP_PKEY_assign_EC_KEY(keypair, ECDSA->eckey))
        errorLog("Couldn't assign keypair");

    FILE *fp = fopen(path, "a");
    
    if(!fp) errorLog("Couldn't open file");
    

    if (!PEM_write_EC_PUBKEY(fp, keypair)) 
        errorLog("Error writing public key to file");

    fclose(fp);
    EVP_PKEY_free(keypair);

}

void save_private_key(EDCSA_key_pair* ECDSA, char path[])
{
    EVP_PKEY *keypair = EVP_PKEY_new();

    if(!keypair) errorLog("Couldn't create keypair");

    if(!EVP_PKEY_assign_EC_KEY(keypair, ECDSA->eckey))
        errorLog("Couldn't assign keypair");

    FILE *fp = fopen(path, "a");

    if(!fp) errorLog("Couldn't open file");

    if(!PEM_write_ECPrivateKey(fp, keypair,NULL, NULL, 0, NULL, NULL))
        errorLog("Error writing private key to file");

    fclose(fp);
    EVP_PKEY_free(keypair);
}

int sign_Challenge( EDCSA_key_pair* ECDSA, const unsigned char *challenge, 
                    int challenge_len, unsigned char *signature, 
                    size_t *signature_len)
{
    size_t sig_size = ECDSA_size(ECDSA->eckey);
    ECDSA_sign(1,challenge, challenge_len, signature, sig_size, ECDSA->eckey);
    *signature_len = sig_size;

    return *signature_len;
}

int verify_challenge(EDCSA_key_pair* ECDSA, const unsigned char *challenge, 
                    int challenge_len, const unsigned char *signature, 
                    size_t* signature_len)
{
    size_t sig_size = ECDSA_size(ECDSA->eckey);
    int res = ECDSA_verify(1,challenge, challenge_len, signature, sig_size, ECDSA->eckey);
    
    return res;
}

int read_auth_key(EDCSA_key_pair* ECDSA, char path[], char* pattern)
{
    FILE* pipe;
    if(!has_Pattern(path,pattern,pipe))
    {
        return Faillure;
    }
    
    ECDSA->eckey = PEM_read_PUBKEY(pipe,NULL,NULL,NULL);

    if(!ECDSA->eckey) errorLog("Could not read public key\n");

    pclose(pipe);

    return Success;

}

int read_private_key(EDCSA_key_pair* ECDSA, char path[])
{
    if(notExist(path))
        return Faillure;

    FILE* fp = fopen(path, "rb");
    ECDSA->eckey = PEM_read_PrivateKey(fp,NULL,NULL,NULL);  

    if(!ECDSA->eckey) errorLog("Could not read private key\n");

    return Success;
}