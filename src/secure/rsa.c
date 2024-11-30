#include "rsa.h"
#include "common/common.h"
#include "common/file.h"
#include <string.h>
#include <openssl/rsa.h>
#include <node/openssl/rsa.h>
#include <openssl/err.h>
#include <log/ftplog.h>
#include "hash.h"
#include <openssl/core_names.h>

#ifdef OPENSSL_3
void generate_rsa_key_pair(EVP_PKEY **pkey)
{
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx)
    {
        unsigned long err_code = ERR_get_error();
        if (err_code) 
        {
            char err_buf[120];
            ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
            fprintf(stderr, "Error: %s\n", err_buf);
        }
        return;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        unsigned long err_code = ERR_get_error();
        if (err_code) 
        {
            char err_buf[120];
            ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
            fprintf(stderr, "Error: %s\n", err_buf);
        }
        return;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, KEY_SIZE) <= 0)
    {
        unsigned long err_code = ERR_get_error();
        if (err_code) 
        {
            char err_buf[120];
            ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
            fprintf(stderr, "Error: %s\n", err_buf);
        }
        return;
    }

    if (EVP_PKEY_keygen(ctx, pkey) <= 0)
    {
        unsigned long err_code = ERR_get_error();
        if (err_code) 
        {
            char err_buf[120];
            ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
            fprintf(stderr, "Error: %s\n", err_buf);
        }
        return;
    }

    EVP_PKEY_CTX_free(ctx);

}

void save_rsa_public_key(char path[], EVP_PKEY *pkey)
{
    FILE* fp = fopen(path, "w");

    if (!fp)
    {
        unsigned long err_code = ERR_get_error();
        if (err_code) 
        {
            char err_buf[120];
            ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
            fprintf(stderr, "Error opening public key file: %s\n", err_buf);
        }
        return; 
    }

    if (!PEM_write_PUBKEY(fp, pkey))
    {
        unsigned long err_code = ERR_get_error();
        if (err_code)
        {
            char err_buf[120];
            ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
            fprintf(stderr, "Error writing public key to file: %s\n", err_buf);
        }
    }

    fclose(fp);  
}

void save_rsa_private_key(char path[], EVP_PKEY *pkey)
{
    FILE* fp = fopen(path, "w");  

    if (!fp)
    {
        unsigned long err_code = ERR_get_error();
        if (err_code) 
        {
            char err_buf[120];
            ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
            fprintf(stderr, "Error opening private key file: %s\n", err_buf);
        }
        return;  
    }

    if (!PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL))
    {
        unsigned long err_code = ERR_get_error();
        if (err_code)
        {
            char err_buf[120];
            ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
            fprintf(stderr, "Error writing private key to file: %s\n", err_buf);
        }
    }

    fclose(fp); 
}

int rsa_pub_encrypt(EVP_PKEY* pkey, BIGNUM** inbn, BIGNUM** outbn)
{
    unsigned char *in, *out;
	size_t inlen, outlen;

    inlen = BN_num_bytes(*inbn) ;
    in = (unsigned char*) malloc(inlen);

	memset(in, 0, inlen);

    BN_bn2bin(*inbn, in);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);

    if(!ctx)
    {
        free(in);
        unsigned long err_code = ERR_get_error();
        if (err_code) 
        {
            char err_buf[120];
            ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
            fprintf(stderr, "Error: %s\n", err_buf);
        }
        return 0;
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0)
    {
        free(in);
        EVP_PKEY_CTX_free(ctx);
        unsigned long err_code = ERR_get_error();
        if (err_code) 
        {
            char err_buf[120];
            ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
            fprintf(stderr, "Error: %s\n", err_buf);
        }
        return 0;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
    {
        free(in);
        EVP_PKEY_CTX_free(ctx);
        unsigned long err_code = ERR_get_error();
        if (err_code) 
        {
            char err_buf[120];
            ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
            fprintf(stderr, "Error: %s\n", err_buf);
        }
        return 0;
    }

    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, in, inlen) <= 0)
    {
        free(in);
        EVP_PKEY_CTX_free(ctx);
        unsigned long err_code = ERR_get_error();
        if (err_code) 
        {
            char err_buf[120];
            ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
            fprintf(stderr, "Error: %s\n", err_buf);
        }
        return 0;
    }   

    out = OPENSSL_malloc(outlen);
    memset(out, 0, outlen);

    if (!out)   
    {
        free(in);
        EVP_PKEY_CTX_free(ctx);
        perror("Fail allocate memory");
        return 0;
    }


    if (EVP_PKEY_encrypt(ctx, out, &outlen, in, inlen) <= 0)
    {
        free(in);
        free(out);
        EVP_PKEY_CTX_free(ctx);
        unsigned long err_code = ERR_get_error();
        if (err_code) 
        {
            char err_buf[120];
            ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
            fprintf(stderr, "Error: %s\n", err_buf);
        }
        return 0;
    }

    LOG(1, "OUTLEN0 : %d\n", outlen);

    BN_bin2bn(out, outlen, *outbn);

    EVP_PKEY_CTX_free(ctx);
    memset(out, 0, outlen);
	memset(in, 0, inlen);
	free(out);
	free(in);

    return 1;

}

int rsa_pub_decrypt(EVP_PKEY* pkey, BIGNUM** inbn, BIGNUM** outbn)
{
    unsigned char *in, *out;
	size_t inlen, outlen;

    inlen = BN_num_bytes(*inbn) ;
    in = (unsigned char*) malloc(inlen);

	memset(in, 0, inlen);
    BN_bn2bin(*inbn, in);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);

    if (EVP_PKEY_decrypt_init(ctx) <= 0)
    {
        free(in);
        unsigned long err_code = ERR_get_error();
        if (err_code) 
        {
            char err_buf[120];
            ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
            fprintf(stderr, "Error: %s\n", err_buf);
        }
        return 0;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
    {
        free(in);
        EVP_PKEY_CTX_free(ctx);
        unsigned long err_code = ERR_get_error();
        if (err_code) 
        {
            char err_buf[120];
            ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
            fprintf(stderr, "Error: %s\n", err_buf);
        }
        return 0;
    }

    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, in, inlen) <= 0)
    {
        free(in);
        EVP_PKEY_CTX_free(ctx);
        unsigned long err_code = ERR_get_error();
        if (err_code) 
        {
            char err_buf[120];
            ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
            fprintf(stderr, "Error: %s\n", err_buf);
        }
        return 0;
    }   

    out = OPENSSL_malloc(outlen);
    memset(out, 0, outlen);

    if (!out)   
    {
        free(in);
        EVP_PKEY_CTX_free(ctx);
        perror("Fail allocate memory");
        return 0;
    }

    if (EVP_PKEY_decrypt(ctx, out, &outlen, in, inlen) <= 0)
    {
        free(in);
        free(out);
        EVP_PKEY_CTX_free(ctx);
        unsigned long err_code = ERR_get_error();
        if (err_code) 
        {
            char err_buf[120];
            ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
            fprintf(stderr, "Error: %s\n", err_buf);
        }
        ERR_print_errors_fp(stderr); 
        return 0;
    }

    // LOG(1, "OUTLEN1 : %d\n", outlen);
    // LOG(1, "INLEN1 : %d\n", inlen);

    BN_bin2bn(out, outlen, *outbn);

    EVP_PKEY_CTX_free(ctx);
    memset(out, 0, outlen);
	memset(in, 0, inlen);
	free(out);
	free(in);

    return 1;
}

int load_rsa_auth_key(EVP_PKEY **pkey, char path[])
{
    FILE *fp = fopen(public_RSAkey_file, "rb");

    if(!fp)
    {
        fclose(fp);
        fatal("Could not open private key file\n");
    }

    if(!(*pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL)))
    {
        unsigned long err_code = ERR_get_error();
        if (err_code) 
        {
            char err_buf[120];
            ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
            fprintf(stderr, "Error: %s\n", err_buf);
        }
        return 0;
    }

    fclose(fp);

    return 1;
}

int load_private_rsa_key(EVP_PKEY **pkey, char path[])
{
    FILE* fp = fopen(private_RSAkey_file, "r");

    if(!fp)
    {
        fclose(fp);
        fatal("Could not open private key file\n");
    }

    if(!(*pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL)))
    {
        unsigned long err_code = ERR_get_error();
        if (err_code) 
        {
            char err_buf[120];
            ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
            fprintf(stderr, "Error: %s\n", err_buf);
        }
        return 0;
    }

    fclose(fp);
}

void rsa_pubkey_hash(EVP_PKEY* pub_key, char** ret,  int* retlen)
{
    unsigned char *nbuf, *ebuf, *bbuf;
    unsigned int ttlen, nlen, elen;
    BIGNUM* e = BN_new();
    BIGNUM* n = BN_new();

    if (!EVP_PKEY_get_bn_param(pub_key, OSSL_PKEY_PARAM_RSA_N, &n) || 
        !EVP_PKEY_get_bn_param(pub_key, OSSL_PKEY_PARAM_RSA_E, &e)) 
    {
        ERR_print_errors_fp(stderr);
        BN_free(e);
        BN_free(n);
        return;
    }

    nlen  = BN_num_bits(n);
    elen = BN_num_bits(e);
    ttlen += nlen;
    ttlen += elen;

    nbuf = (char*) malloc(nlen);
    bbuf = (char*) malloc(ttlen);
    ebuf = (char*) malloc(elen);

    BN_bn2bin(n, nbuf);
    BN_bn2bin(e, ebuf);

    strncpy(bbuf, nbuf, nlen);
    strncpy(bbuf, ebuf, elen);

    sha256(bbuf, ttlen, ret, retlen);

    free(nbuf);
    free(ebuf);
    free(bbuf); 
    BN_free(n);
    BN_free(e);
}

#elif OPENSSL_1

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

    if (!*pub_key) 
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

    if (!*private_key) 
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

void rsa_pubkey_hash(RSA* pubkey, char** ret, int* retlen)
{
    BIGNUM *e, *n;
    unsigned char *nbuf, *ebuf, *bbuf;
    unsigned int ttlen, nlen, elen;

    RSA_get0_key(pub_key, &n, &e, NULL );
    nlen  = BN_num_bits(n);
    elen = BN_num_bits(e);
    ttlen += nlen;
    ttlen += elen;

    nbuf = (char*) malloc(nlen);
    bbuf = (char*) malloc(ttlen);
    ebuf = (char*) malloc(elen);

    BN_bn2bin(n, nbuf);
    BN_bn2bin(e, ebuf);

    strncpy(bbuf, nbuf, nlen);
    strncpy(bbuf, ebuf, elen);

    sha256(bbuf, ttlen, ret, retlen);

    free(nbuf);
    free(ebuf);
    free(bbuf);  
}   

#endif