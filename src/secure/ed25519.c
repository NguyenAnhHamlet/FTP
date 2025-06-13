#include "ed25519.h"
#include "common/common.h"
#include "log/ftplog.h"
#include "hash.h" 
#include <openssl/core_names.h>

extern void openssl_get_error();

void generate_ed25519_key_pair(EVP_PKEY **pkey)
{
    *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_keygen(pctx, pkey);
    EVP_PKEY_CTX_free(pctx);
}

void save_ed25519_public_key(char path[], EVP_PKEY *pkey)
{
    FILE* fp = fopen(path, "w");

    if (!fp)
    {
        unsigned long err_code = ERR_get_error();
        if (err_code) 
        {
            char err_buf[120];
            ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
            fprintf(stderr, "Error opening public key file: %s\n", 
                    err_buf);
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
            fprintf(stderr, "Error writing public key to file: %s\n", 
                    err_buf);
        }
    }

    fclose(fp);  
}

void save_ed25519_private_key(char path[], EVP_PKEY *pkey)
{
    FILE* fp = fopen(path, "w");  

    if (!fp)
    {
        unsigned long err_code = ERR_get_error();
        if (err_code) 
        {
            char err_buf[120];
            ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
            fprintf(stderr, "Error opening private key file: %s\n", 
                    err_buf);
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
            fprintf(stderr, "Error writing private key to file: %s\n", 
                    err_buf);
        }
    }

    fclose(fp); 
}

int ed25519_priv_sign(EVP_PKEY* pkey, BIGNUM** inbn, BIGNUM** signbn)
{
    unsigned char *in, *sign;
	size_t inlen, signlen;
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;

    inlen = BN_num_bytes(*inbn) ;
    in = (unsigned char*) malloc(inlen);

	memset(in, 0, inlen);
    BN_bn2bin(*inbn, in);

    mdctx = EVP_MD_CTX_create();

    if(!mdctx)
    {
        free(in);
        EVP_PKEY_CTX_free(pctx);
        EVP_MD_CTX_destroy(mdctx);
        openssl_get_error();
        return 0;
    }

    if(!EVP_DigestSignInit(mdctx, NULL, NULL, NULL, pkey))
    {
        free(in);
        EVP_MD_CTX_destroy(mdctx);
        openssl_get_error();
        return 0;
    }

    if(!EVP_DigestSign(mdctx, NULL, &signlen, in, inlen))
    {
        free(in);
        EVP_MD_CTX_destroy(mdctx);
        openssl_get_error();
        return 0;
    }

    sign = (char*) malloc(signlen);

    if(!EVP_DigestSign(mdctx, sign, &signlen, in, inlen))
    {
        free(in);
        EVP_MD_CTX_destroy(mdctx);
        openssl_get_error();
        return 0;
    }

    BN_bin2bn(sign, signlen, *signbn);
    EVP_MD_CTX_destroy(mdctx);
    free(in);
    free(sign);

    return 1;
}

int ed25519_pub_verify(EVP_PKEY* pkey, BIGNUM** inbn, BIGNUM** signbn)
{
    unsigned char *in, *sign;
	size_t inlen, signlen;
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;

    inlen = BN_num_bytes(*inbn) ;
    in = (unsigned char*) malloc(inlen);
    signlen = BN_num_bytes(*signbn) ;
    sign = (unsigned char*) malloc(signlen);

	memset(in, 0, inlen);
    BN_bn2bin(*inbn, in);
    memset(sign, 0, signlen);
    BN_bn2bin(*signbn, sign);

    mdctx = EVP_MD_CTX_create();

    if(!mdctx)
    {
        free(in);
        free(sign);
        EVP_MD_CTX_destroy(mdctx);
        openssl_get_error();
        return 0;
    }

    if(!EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pkey))
    {
        free(in);
        free(sign);
        EVP_MD_CTX_destroy(mdctx);
        openssl_get_error();
        return 0;
    }


    if(!EVP_DigestVerify(mdctx, sign, signlen, in, inlen))
    {
        free(in);
        free(sign);
        EVP_MD_CTX_destroy(mdctx);
        openssl_get_error();
        return 0;
    }

    free(in);
    free(sign);
    EVP_MD_CTX_destroy(mdctx);

    return 1;
}

int load_ed25519_auth_key(EVP_PKEY **pkey, char path[])
{
    FILE *fp = fopen(PUBLIC_ED25519, "rb");

    if(!fp)
    {
        fclose(fp);
        fatal("Could not open public key file\n");
    }

    if(!(*pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL)))
    {
        openssl_get_error();
        return 0;
    }

    fclose(fp);

    return 1;
}

int load_private_ed25519_key(EVP_PKEY **pkey, char path[])
{
    FILE* fp = fopen(PRIVATE_ED25519, "r");

    if(!fp)
    {
        fclose(fp);
        fatal("Could not open private key file\n");
    }

    if(!(*pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL)))
    {
        openssl_get_error();
        return 0;
    }

    fclose(fp);
}

void ed25519_pubkey_hash(EVP_PKEY* pub_key, char** ret, int* retlen)
{
    size_t pubkeystr_len = 0;
    if (!EVP_PKEY_get_octet_string_param(pub_key, 
                                         OSSL_PKEY_PARAM_PUB_KEY, 
                                         NULL, 0, &pubkeystr_len)) 
    {
        ERR_print_errors_fp(stderr);
        return ;                                                                                                                                   
    }

    unsigned char *pubkeystr = OPENSSL_malloc(pubkeystr_len);

    if (!EVP_PKEY_get_octet_string_param(pub_key, 
                                         OSSL_PKEY_PARAM_PUB_KEY, 
                                         pubkeystr, pubkeystr_len, 
                                         &pubkeystr_len)) 
    {
        ERR_print_errors_fp(stderr);
        OPENSSL_free(pubkeystr);
        return;
    }

    if (!pubkeystr) 
    {
        ERR_print_errors_fp(stderr);
        return;
    }

    LOG(SERVER_LOG, "HERE 0\n");

    sha256(pubkeystr, pubkeystr_len, ret, retlen);

    LOG(SERVER_LOG, "HERE 2\n");

    OPENSSL_free(pubkeystr);
}