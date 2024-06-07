#include "rsa.h"
#include "common.h"
#include "file.h"
#include <string.h>

void generate_RSA_KEYPAIR(RSA * rsa)
{
    rsa = RSA_new();
    if (!rsa) fatal("Could not initialize object rsa\n");

    if (RSA_generate_key_ex(rsa, KEY_SIZE, RSA_3, NULL) != 1) 
       fatal("Could not generate RSA key pair\n");
}

void save_RSApublic_key(RSA * rsa, char path[])
{
    FILE* fp = fopen(path, "wb");

    if(!PEM_write_RSAPublicKey(fp, rsa))
        fatal("Could not write RSA public key");

    fclose(fp);
}

void save_RSAprivate_key(RSA * rsa, char path[])
{
    FILE* fp = fopen(path, "wb");

    if(!PEM_write_RSAPrivateKey(fp, rsa, NULL, NULL, NULL, NULL, NULL ))
        fatal("Could not write RSA private key");

    fclose(fp);
}

int rsa_pub_encrypt( RSA * rsa, const unsigned char *challenge, 
                    int challenge_len, unsigned char *signature, 
                    size_t *signature_len)
{
    EVP_PKEY_CTX *ctx;
    char *inbuf, *outbuf;
	int len, ilen, olen;

    ctx = EVP_PKEY_CTX_new();
    size_t sig_size = RSA_size(rsa);

    olen = BN_num_bytes(rsa);                       // might be an issue
	outbuf = (char*)malloc(olen);

	ilen = BN_num_bytes(in);
	inbuf = (char*)malloc(ilen);
	BN_bn2binpad(signature, inbuf, ilen);

    if (EVP_PKEY_encrypt_init_ex(ctx, NULL, NULL, rsa) != 1) 
    {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if (EVP_PKEY_encrypt(ctx, inbuf, &ilen, outbuf, olen) != 1) 
    {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    BN_bin2bn(outbuf, len, signature);
    *signature_len = olen;

    return *signature_len;
}

int rsa_priv_decrypt(RSA * rsa, BIGNUM *challenge, 
                    int challenge_len, BIGNUM *signature, 
                    size_t* signature_len)
{
    EVP_PKEY_CTX *ctx;
	char *inbuf, *outbuf;
	int len, ilen, olen;

    ctx = EVP_PKEY_CTX_new();

	olen = BN_num_bytes(rsa);                           // might be an issue
	outbuf = (char*)malloc(olen);

	ilen = BN_num_bytes(signature);
	inbuf = (char*)malloc(ilen);
	BN_bn2binpad(signature, inbuf, ilen);

    if (EVP_PKEY_decrypt_init_ex(ctx, NULL, NULL, rsa) != 1) 
    {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if (EVP_PKEY_decrypt(ctx, outbuf, olen, inbuf, ilen) != 1) 
    {
        ERR_print_errors_fp(stderr);
        return -1;
    }

	BN_bin2bn(outbuf, len, challenge);

	memset(outbuf, 0, olen);
	memset(inbuf, 0, ilen);
	free(outbuf);
	free(inbuf);
}

int read_RSAauth_key(RSA * rsa, char path[], char* pattern)
{
    FILE* pipe;
    if(!has_Pattern(path,pattern,pipe))
    {
        return Faillure;
    }
    
    rsa = PEM_read_RSA_PUBKEY(pipe,NULL,NULL,NULL);

    if(!rsa) fatal("Could not read public key\n");

    pclose(pipe);

    return Success;
}

int read_privateRSA_key(RSA * rsa, char path[])
{
    FILE* pipe;
    
    rsa = PEM_read_RSAPrivateKey(pipe,NULL,NULL,NULL);

    if(!rsa) fatal("Could not read private key\n");

    pclose(pipe);

    return Success;
}