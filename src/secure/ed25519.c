#include "ed25519.h"
#include "common/common.h"

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

    pctx = NULL; //EVP_PKEY_CTX_new(pkey, NULL);
    mdctx = EVP_MD_CTX_create();

    if(!pctx || !mdctx)
    {
        free(in);
        EVP_PKEY_CTX_free(pctx);
        EVP_MD_CTX_destroy(mdctx);
        openssl_get_error();
        return 0;
    }

    // assign the pkey context for mdctx
    // EVP_MD_CTX_set_pkey_ctx(mdctx, pctx);

    if(!EVP_DigestSignInit(mdctx, &pctx, EVP_sha512(), NULL, pkey))
    {
        free(in);
        EVP_MD_CTX_destroy(mdctx);
        openssl_get_error();
        return 0;
    }

    if(!EVP_DigestSignUpdate(mdctx, in, inlen))
    {
        free(in);
        EVP_MD_CTX_destroy(mdctx);
        openssl_get_error();
        return 0;
    }

    /* Finalise the DigestSign operation */
    /* First call EVP_DigestSignFinal with a NULL sig parameter to obtain the length of the
    * signature. Length is returned in slen */
    if(!EVP_DigestSignFinal(mdctx, NULL, &signlen)) 
    {
        free(in);
        EVP_MD_CTX_destroy(mdctx);
        openssl_get_error();
        return 0;
    }

    sign = (char*) malloc(signlen);

    // Sign the data now
    if(!EVP_DigestSignFinal(mdctx, sign, &signlen)) 
    {
        free(in);
        EVP_MD_CTX_free(mdctx);
        openssl_get_error();
        return 0;
    } 

    BN_bin2bn(sign, signlen, *signbn);

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
    signlen = BN_num_bytes(*inbn) ;
    sign = (unsigned char*) malloc(inlen);

	memset(in, 0, inlen);
    BN_bn2bin(*inbn, in);
    memset(sign, 0, signlen);
    BN_bn2bin(*signbn, sign);

    pctx = NULL ; //EVP_PKEY_CTX_new(pkey, NULL);
    mdctx = EVP_MD_CTX_create();

    if(!pctx || !mdctx)
    {
        free(in);
        EVP_MD_CTX_destroy(mdctx);
        openssl_get_error();
        return 0;
    }

    // assign the pkey context for mdctx
    // EVP_MD_CTX_set_pkey_ctx(mdctx, pctx);

    if(!EVP_DigestVerifyInit(mdctx, &pctx, EVP_sha512(), NULL, pkey))
    {
        free(in);
        EVP_MD_CTX_destroy(mdctx);
        openssl_get_error();
        return 0;
    }

    if(!EVP_DigestVerifyUpdate(mdctx, in, inlen))
    {
        free(in);
        EVP_MD_CTX_destroy(mdctx);
        openssl_get_error();
        return 0;
    }

    if(EVP_DigestVerifyFinal(mdctx, sign, signlen))
    {
        if(mdctx)
        {
            EVP_MD_CTX_destroy(mdctx);
        }
        return 1;
    }
    
    if(mdctx)
    {
        EVP_MD_CTX_destroy(mdctx);
    }
    return 0;
}

int load_ed25519_auth_key(EVP_PKEY **pkey, char path[])
{
    FILE *fp = fopen(PUBLIC_ED25519, "rb");

    if(!fp)
    {
        fclose(fp);
        fatal("Could not open private key file\n");
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