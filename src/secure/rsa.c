#include "rsa.h"
#include "common/common.h"
#include "common/file.h"
#include <string.h>
#include <openssl/rsa.h>

void generate_RSA_KEYPAIR(RSA *key_pair)
{
    if(!key_pair)
    {
        fatal("rsa object has yet been initialized\n");
    }

    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4); 

    if (RSA_generate_key_ex(key_pair, KEY_SIZE, e, NULL) != 1) 
       fatal("Could not generate RSA key pair\n");
}

void save_RSApublic_key(RSA * rsa, char path[])
{
    FILE* fp = fopen(path, "w");

    if(!fp)
    {
        fclose(fp);
        fatal("Could not open public key file\n");
    }

    if(!PEM_write_RSAPublicKey(fp, rsa))
    {
        fclose(fp);
        fatal("Could not write RSA public key");
    }

    fclose(fp);
}

void save_RSAprivate_key(RSA * rsa, char path[])
{
    FILE* fp = fopen(path, "w");

    if(!fp)
    {
        fclose(fp);
        fatal("Could not open private key file\n");
    }
        

    if(!PEM_write_RSAPrivateKey(fp, rsa, NULL, NULL, KEY_SIZE, NULL, NULL ))
    {
        fclose(fp);
        fatal("Could not write RSA private key");
    }

    fclose(fp);
}

int rsa_pub_encrypt(RSA * rsa, BIGNUM *challenge, 
                    int challenge_len, BIGNUM *signature, 
                    size_t *signature_len)
{
    EVP_PKEY_CTX *ctx;
    char *inbuf, *outbuf;
	int len, ilen, olen;
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, rsa);
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    size_t sig_size = RSA_size(rsa);              

	ilen = BN_num_bytes(signature);
	inbuf = (char*)malloc(ilen);

    if (EVP_PKEY_encrypt(ctx, outbuf, (size_t*) &olen, inbuf, ilen) <= 0)
    {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return -1;        
    }

    outbuf = (char*)malloc(olen);

	BN_bn2binpad(signature, inbuf, ilen);

    if (EVP_PKEY_encrypt_init(ctx) != 1) 
    {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return -1;
    }

    if (EVP_PKEY_encrypt(ctx, inbuf, (size_t*) &ilen, outbuf, olen) != 1) 
    {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return -1;
    }

    BN_bin2bn(outbuf, len, signature);
    *signature_len = olen;

    return *signature_len;
}

int rsa_pub_decrypt(RSA * rsa, BIGNUM *challenge, 
                    int challenge_len, BIGNUM *signature, 
                    size_t* signature_len)
{
    EVP_PKEY_CTX *ctx;
	char *inbuf, *outbuf;
	int len, ilen, olen;
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, rsa);
    ctx = EVP_PKEY_CTX_new(pkey, NULL);

    if (EVP_PKEY_encrypt(ctx, NULL, (size_t*) &olen, inbuf, ilen) <= 0)
    {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return -1;        
    }

    outbuf = (char*)malloc(olen);

	ilen = BN_num_bytes(signature);
	inbuf = (char*)malloc(ilen);
	BN_bn2binpad(signature, inbuf, ilen);

    if (EVP_PKEY_decrypt_init(ctx) != 1) 
    {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if (EVP_PKEY_decrypt(ctx, outbuf, (size_t*) &olen, inbuf, ilen) != 1) 
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

int load_rsa_auth_key(RSA **pub_key, char path[])
{
    FILE *fp = fopen(public_RSAkey_file, "r");
    if (!fp) 
    {
        fatal("Could not open pipe\n");
    }

    *pub_key = PEM_read_RSAPublicKey(fp,NULL,NULL,NULL);

    if (!pub_key) 
    {
        BIO *bio = BIO_new(BIO_s_file());
        BIO_set_fp(bio, stderr, BIO_NOCLOSE);
        ERR_print_errors(bio);
        BIO_free(bio);
        fatal("Could not read public key\n");
    }

    fclose(fp);

    return 1;
}

int load_private_rsa_key(RSA **private_key, char path[])
{
    FILE *fp = fopen(private_RSAkey_file, "r");
    if (!fp) 
    {
        fatal("Could not open pipe\n");
    }
    
    *private_key = PEM_read_RSAPrivateKey(fp,NULL,NULL,NULL);

    if (!private_key) 
    {
        BIO *bio = BIO_new(BIO_s_file());
        BIO_set_fp(bio, stderr, BIO_NOCLOSE);
        ERR_print_errors(bio);
        BIO_free(bio);
        fatal("Could not read private key\n");
    }

    fclose(fp);
    return Success;
}

void rsa_read_public_key(char path[], char* key)
{
    if(not_exist(path))
        fatal("File %s does not exist\n");
    
    if(!key) 
    {   
        FILE* pub_file;
        read_file(path, pub_file);

        fseek(pub_file, 0, SEEK_END);
        int pub_size = ftell(pub_file);
        fseek(pub_file, 0, SEEK_SET);

        key = (char*) malloc(pub_size);

        if(!key) 
            fatal("Could not allocate memory to store public key\n");

        fread(key, 1, pub_size, pub_file);
    }
}

void rsa_read_private_key(char path[], char* key)
{
    if(not_exist(path))
        fatal("File %s does not exist\n");
    
    if(!key) 
    {   
        FILE* pub_file;
        read_file(path, pub_file);

        fseek(pub_file, 0, SEEK_END);
        int pub_size = ftell(pub_file);
        fseek(pub_file, 0, SEEK_SET);

        key = (char*) malloc(pub_size);

        if(!key) 
            fatal("Could not allocate memory to store private key\n");

        fread(key, 1, pub_size, pub_file);
    }
}