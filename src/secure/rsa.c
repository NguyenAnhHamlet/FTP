#include "rsa.h"
#include "common/common.h"
#include "common/file.h"
#include <string.h>
#include <openssl/rsa.h>
#include <node/openssl/rsa.h>
#include <openssl/err.h>
#include <log/ftplog.h>

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

int rsa_pub_encrypt(RSA * pub, BIGNUM** in, BIGNUM** out)
{
    char *inbuf, *outbuf;
	int len, ilen, olen;

    const BIGNUM* n = RSA_get0_n(pub);

    olen = BN_num_bytes(n);
    outbuf = (char*) malloc(olen);

    ilen = BN_num_bytes(*in);
    inbuf = (char*) malloc(ilen);

    memset(outbuf, 0, olen);
	memset(inbuf, 0, ilen);

    BN_bn2bin(*in, inbuf);

    if ((len = RSA_public_encrypt(ilen, inbuf, outbuf, pub,
				      RSA_PKCS1_PADDING)) <= 0)
	{
        unsigned long err = ERR_get_error();
        char *error_str = ERR_error_string(err, NULL);
        fatal("ENCRYPT : %s\n", error_str);
    }

    BN_bin2bn(outbuf, len, *out);
    olen = BN_num_bytes(*out);

    memset(outbuf, 0, olen);
	memset(inbuf, 0, ilen);
	free(outbuf);
	free(inbuf);

    return len;
}

int rsa_pub_decrypt(RSA * priv, BIGNUM** in, BIGNUM** out)
{
	char *inbuf, *outbuf;
	int len, ilen, olen;

	const BIGNUM* n = RSA_get0_n(priv);

    olen = BN_num_bytes(n);
	outbuf = (char*) malloc(olen);

	ilen = BN_num_bytes(*in);
	inbuf = (char*) malloc(ilen);

    memset(outbuf, 0, olen);
	memset(inbuf, 0, ilen);

    BN_bn2bin(*in, inbuf);

    LOG(SERVER_LOG, "SIZE 2: %d\n", ilen);
    LOG(SERVER_LOG, "SIZE 2: %d\n", olen);

	if ((len = RSA_private_decrypt(ilen, inbuf, outbuf, priv,
				       RSA_PKCS1_PADDING)) <= 0)
	{
        unsigned long err = ERR_get_error();
        char *error_str = ERR_error_string(err, NULL);
        fatal("DECRYPT : %s\n", error_str);
    }

	BN_bin2bn(outbuf, len, *out);

	memset(outbuf, 0, olen);
	memset(inbuf, 0, ilen);
	free(outbuf);
	free(inbuf);   
}

int load_rsa_auth_key(RSA **pub_key, char path[])
{
    FILE *fp = fopen(public_RSAkey_file, "r");
    RSA* t = RSA_new();
    if (!fp) 
    {
        fatal("Could not open pipe\n");
    }

    *pub_key = PEM_read_RSAPublicKey(fp, &t, NULL, NULL);

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
    RSA* t = RSA_new();
    if (!fp) 
    {
        fatal("Could not open pipe\n");
    }
    
    *private_key = PEM_read_RSAPrivateKey(fp, &t, NULL, NULL);

    if (! *private_key) 
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