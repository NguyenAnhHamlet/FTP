#include "kex.h"
#include <openssl/bn.h>
#include "log/ftplog.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>

#ifdef OPENSSL_1
DH* dh_creation()
{
    const char *gen = "2", *prime =
        "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1"
        "D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9"
        "7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD6561"
        "2433F51F5F066ED0856365553DED1AF3B557135E7F57C935"
        "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE735"
        "30ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB"
        "B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB19"
        "0B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61"
        "9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD73"
        "3BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA"
        "886B423861285C97FFFFFFFFFFFFFFFF";

    DH *dh;
    BIGNUM *p, *g, *q, *p_cp;

    p = BN_new();
    g = BN_new();
    p_cp = BN_new();
    q = BN_new();

    dh = DH_new();
    if(!dh) return NULL;

    // convert to BIGNUM value
    if(!BN_hex2bn(&g, gen) || !BN_hex2bn(&p, prime) || !BN_hex2bn(&p_cp, prime))
    {
        DH_free(dh);
        BN_clear_free(p);
        BN_clear_free(g);
        BN_clear_free(p_cp);
        BN_clear_free(q);
        return NULL; 
    }

    if (!BN_sub_word(p_cp, 1) || !BN_rshift1(q, p_cp))
    {
        DH_free(dh);
        BN_clear_free(p);
        BN_clear_free(g);
        BN_clear_free(p_cp);
        BN_clear_free(q);
        return NULL;
    }

    if (!DH_set0_pqg(dh, p, q, g))
    {
        DH_free(dh);
        BN_clear_free(p);
        BN_clear_free(g);
        BN_clear_free(p_cp);
        BN_clear_free(q);
        return NULL;
    }

    return dh;
}

int generate_keys(DH *dh)
{
    if(!dh) 
        return 0;

    BIGNUM *p = NULL, *g = NULL, *q = NULL;

    DH_get0_pqg(dh, &p, &q, &g);

    if(!p || !g || !q) 
        return 0;

    if (DH_generate_key(dh) == 0)
    {
        unsigned long err_code;
        err_code = ERR_get_error();
        const char *err_string = ERR_error_string(err_code, NULL);
        LOG(SERVER_LOG, "ERROR: %s", err_string);
        return 0;
    }

    return 1;
}

int generate_secret_key(DH* dh, BIGNUM** shared_key, BIGNUM** pub_value)
{
    int key_len;
    unsigned char* key;

    key_len = DH_size(dh);

    key = (unsigned char*) malloc(key_len);

    if(!DH_compute_key(key, *pub_value, dh))
        return 0;
    
    if(!BN_bin2bn(key, key_len, *shared_key))
        return 0;
    
    return 1;
}

#elif OPENSSL_3

void openssl_get_error()
{
    unsigned long err_code = ERR_get_error();
    if (err_code) 
    {
        char err_buf[120];
        ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
        fprintf(stderr, "Error: %s\n", err_buf);
    }
}

EVP_PKEY* EVP_PKEY_DH_init()
{
    int priv_len = 224;
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);

    if(!ctx)
    {
        openssl_get_error();
        return 0;
    }

    if(!EVP_PKEY_keygen_init(ctx))
    {
        openssl_get_error();
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    if(!EVP_PKEY_CTX_set_group_name(ctx, "ffdhe2048"))
    {
        openssl_get_error();
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    if(!EVP_PKEY_generate(ctx, &pkey))
    {
        openssl_get_error();
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    EVP_PKEY_CTX_free(ctx);

    return pkey;
}

int generate_secret_key(EVP_PKEY* pkey, BIGNUM** shared_key, BIGNUM** pub_value)
{
    EVP_PKEY* peer_key = NULL;
    unsigned char *skey;
    size_t skeylen;
    int priv_len = 112 << 1;

    // BN_print_fp(stdout, *pub_value);

    // create a peer key EVP_PKEY
    OSSL_PARAM_BLD *param_builder = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_BN(param_builder, OSSL_PKEY_PARAM_PUB_KEY, *pub_value);
    OSSL_PARAM_BLD_push_utf8_string(param_builder, "group", "ffdhe2048", 0);
    OSSL_PARAM_BLD_push_int(param_builder, "priv_len", priv_len);
    OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(param_builder);
    EVP_PKEY_CTX *peer_ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
    EVP_PKEY_fromdata_init(peer_ctx);
    EVP_PKEY_fromdata(peer_ctx, &peer_key, EVP_PKEY_PUBLIC_KEY, params);

    // clean up
    EVP_PKEY_CTX_free(peer_ctx);
    OSSL_PARAM_BLD_free(param_builder);
    OSSL_PARAM_free(params);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) 
    {
        openssl_get_error();
        EVP_PKEY_free(pkey);
    }

    if (EVP_PKEY_derive_init(ctx) <= 0)
    {
        openssl_get_error();
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return 0;
    }

    LOG(1, "RUNNING 0\n");

    if (EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0)
    {
        openssl_get_error();
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return 0;
    }

    LOG(1, "RUNNING 1\n");

    if (EVP_PKEY_derive(ctx, NULL, &skeylen) <= 0)
    {
        openssl_get_error();
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return 0;
    }

    skey = OPENSSL_malloc(skeylen);

    if (!skey)
    {
        openssl_get_error();
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return 0;
    }

    if (EVP_PKEY_derive(ctx, skey, &skeylen) <= 0)
    {
        openssl_get_error();
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        OPENSSL_free(skey);
        return 0;
    }

    LOG(1, "RUNNING 2\n");

    BN_bin2bn(skey, skeylen, *shared_key);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    OPENSSL_free(skey);

    return 1;
}

#endif




