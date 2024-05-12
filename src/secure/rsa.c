#include "rsa.h"
#include "common.h"
#include "file.h"
#include <string.h>

void generate_RSA_KEYPAIR(RSA * rsa)
{
    rsa = RSA_new();
    if (!rsa) errorLog("Could not initialize object rsa\n");

    if (RSA_generate_key_ex(rsa, KEY_SIZE, RSA_3, NULL) != 1) 
       errorLog("Could not generate RSA key pair\n");
}

void save_RSApublic_key(RSA * rsa, char path[])
{
    FILE* fp = fopen(path, "wb");

    if(!PEM_write_RSAPublicKey(fp, rsa))
        errorLog("Could not write RSA public key");

    fclose(fp);
}

void save_RSAprivate_key(RSA * rsa, char path[])
{
    FILE* fp = fopen(path, "wb");

    if(!PEM_write_RSAPrivateKey(fp, rsa, NULL, NULL, NULL, NULL, NULL ))
        errorLog("Could not write RSA private key");

    fclose(fp);
}

int sign_RSAChallenge( RSA * rsa, const unsigned char *challenge, 
                    int challenge_len, unsigned char *signature, 
                    size_t *signature_len)
{
    size_t sig_size = RSA_size(rsa);
    int res = RSA_sign(NID_sha1, challenge, challenge_len, signature, signature_len, rsa);

    *signature_len = sig_size; 

    return res;
}

int verify_RSAchallenge(RSA * rsa, const unsigned char *challenge, 
                    int challenge_len, const unsigned char *signature, 
                    size_t* signature_len)
{
    size_t sig_size = RSA_size(rsa);
    int res = RSA_verify(NID_sha1, challenge, challenge_len, signature, signature_len, rsa);

    *signature_len = sig_size; 

    return res;
}

int read_RSAauth_key(RSA * rsa, char path[], char* pattern)
{
    FILE* pipe;
    if(!has_Pattern(path,pattern,pipe))
    {
        return Faillure;
    }
    
    rsa = PEM_read_RSA_PUBKEY(pipe,NULL,NULL,NULL);

    if(!rsa) errorLog("Could not read public key\n");

    pclose(pipe);

    return Success;
}

int read_privateRSA_key(RSA * rsa, char path[])
{
    FILE* pipe;
    
    rsa = PEM_read_RSAPrivateKey(pipe,NULL,NULL,NULL);

    if(!rsa) errorLog("Could not read private key\n");

    pclose(pipe);

    return Success;
}