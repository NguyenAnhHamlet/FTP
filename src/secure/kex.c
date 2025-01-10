#include "kex.h"
#include <openssl/bn.h>
#include "log/ftplog.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/pem.h>

extern void openssl_get_error();

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
        BN_clear_free(g);
        BN_clear_free(p);
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
    OSSL_PARAM_BLD_push_utf8_string(param_builder, OSSL_PKEY_PARAM_GROUP_NAME, "ffdhe2048", 0);
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

#ifdef OPENSSL_1
EC_KEY *EC_KEY_ECDH_init()
{
    EC_KEY *key;
	if (NULL == (key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1))) {
		openssl_get_error();
		return NULL;
	}

	if (1 != EC_KEY_generate_key(key)) {
		openssl_get_error();
		return NULL;
	}
	return key;
}

int extract_public_key_values(EC_KEY* ec_key, BIGNUM** x, BIGNUM** y)
{
    *x = EC_POINT_get_affine_coordinates_GFp(ec_key->group, ec_key->pub_key, NULL, *x, NULL);
    *y = EC_POINT_get_affine_coordinates_GFp(ec_key->group, ec_key->pub_key, NULL, *y, NULL); 

    if (x == NULL || y == NULL) {
        LOG(COMMON_LOG, "Error: Failed to get public key coordinates.\n");
        return 0;
    }

    return 1;
}

int generate_secret_key_ecdh(EC_KEY* ec_key, BIGNUM** shared_key, BIGNUM** pub_value_x, BIGNUM** pub_value_y)
{
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1); 
    char* secret;
    unsigned int secret_len;
    int field_size;

    if (group == NULL) 
    {
        LOG(COMMON_LOG, "Error: Failed to create EC_GROUP.\n");
        return 0;
    }

    EC_POINT *peer_pub_key = EC_POINT_new(group);
    if (peer_pub_key == NULL) 
    {
        LOG(COMMON_LOG, "Error: Failed to create EC_POINT.\n");
        EC_GROUP_free(group); 
        return 0;
    }

    if (!EC_POINT_set_affine_coordinates_GFp(group, peer_pub_key, *pub_value_x, *pub_value_y, NULL)) {
        LOG(COMMON_LOG, "Error: Failed to set peer's public key coordinates.\n");
        EC_POINT_free(peer_pub_key);
        EC_GROUP_free(group);
    }

	field_size = EC_GROUP_get_degree(EC_KEY_get0_group(ec_key));
	secret_len = (field_size + 7) / 8;

	if (NULL == (secret = OPENSSL_malloc(*secret_len))) {
		openssl_get_error();
        EC_POINT_free(peer_pub_key);
        EC_GROUP_free(group); 
		return 0;
	}

	secret_len = ECDH_compute_key(secret, secret_len,
					peer_pub_key, ec_key, NULL);

	if (secret_len <= 0) 
    {
        EC_POINT_free(peer_pub_key);
        EC_GROUP_free(group); 
		OPENSSL_free(shared_key);
		return 0;
	}

    BN_bin2bn(secret, secret_len, *shared_key);

    EC_POINT_free(peer_pub_key);
    EC_GROUP_free(group); 
    OPENSSL_free(shared_key);

	return 1;
}

#elif OPENSSL_3
EVP_PKEY* EC_KEY_ECDH_init()
{
    EVP_PKEY_CTX *kctx = NULL , *pctx = NULL;
    EVP_PKEY *pkey = NULL, *params = NULL;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);

    if(pctx == NULL) 
    {
        openssl_get_error();
        EVP_PKEY_CTX_free(pctx);
        return 0;
    }

    if(1 != EVP_PKEY_paramgen_init(pctx))
    {
        openssl_get_error();
        EVP_PKEY_CTX_free(pctx);
        return 0;
    }

    if(1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1)) 
    {
        openssl_get_error();
        EVP_PKEY_CTX_free(pctx);
        return 0;
    }

	if (!EVP_PKEY_paramgen(pctx, &params)) 
    {
        openssl_get_error();
        EVP_PKEY_CTX_free(pctx);
        return 0;
    }

	if(NULL == (kctx = EVP_PKEY_CTX_new(params, NULL)))
    {
        openssl_get_error();
        EVP_PKEY_CTX_free(pctx);
        return 0;
    }

	if(1 != EVP_PKEY_keygen_init(kctx)) 
    {
        openssl_get_error();
        EVP_PKEY_CTX_free(pctx);
        return 0;
    }

	if (1 != EVP_PKEY_keygen(kctx, &pkey)) 
    {
        openssl_get_error();
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_CTX_free(kctx);
        return 0;
    }

    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_CTX_free(kctx);

    return pkey;
}

int extract_public_key_values(EVP_PKEY* evp_key, BIGNUM*** x, BIGNUM*** y)
{
    if(!EVP_PKEY_get_bn_param(evp_key, OSSL_PKEY_PARAM_EC_PUB_X, *x) || 
       !EVP_PKEY_get_bn_param(evp_key, OSSL_PKEY_PARAM_EC_PUB_Y, *y) )
    {
        ERR_print_errors_fp(stderr);
        return 0;
    }

    return 1;
}

// TODO
// Could not generate the EC_KEY in here
int generate_ecdh_from_points(EVP_PKEY** evp_pkey, BIGNUM** x, BIGNUM** y)
{
    unsigned char pub_key_bytes[65];
    pub_key_bytes[0] = 0x04;

    int x_len = BN_num_bytes(*x);
    int y_len = BN_num_bytes(*y);

    BN_bn2binpad(*x, pub_key_bytes + 1, 32);
    BN_bn2binpad(*y, pub_key_bytes + 33, 32); 

    OSSL_PARAM_BLD *params_build = OSSL_PARAM_BLD_new();

    if(!OSSL_PARAM_BLD_push_utf8_string(params_build, OSSL_PKEY_PARAM_GROUP_NAME, SN_X9_62_prime256v1, 0))
    {
        LOG(SERVER_LOG, "Error: failed to push ec_group into param build.\n");
        OSSL_PARAM_BLD_free(params_build);
        return 0;
    }

    if (!OSSL_PARAM_BLD_push_octet_string(params_build, OSSL_PKEY_PARAM_PUB_KEY, pub_key_bytes, sizeof(pub_key_bytes))) 
    {
        LOG(SERVER_LOG, "Error: failed to push public key into param build.\n");
        OSSL_PARAM_BLD_free(params_build);
        return 0;
    }

    OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(params_build);
    if ( params == NULL ) 
    {
        LOG(SERVER_LOG, "Error: failed to construct params from build.\n");
        OSSL_PARAM_BLD_free(params_build);
        OSSL_PARAM_free(params);
        return 0;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);

    if (!ctx) 
    {
        LOG(SERVER_LOG, "Error: Failed to create EVP_PKEY_CTX.\n");
        OSSL_PARAM_free(params);
        OSSL_PARAM_BLD_free(params_build);
        return 0;
    }

    *evp_pkey = NULL;

    if(ctx == NULL || 
       EVP_PKEY_fromdata_init(ctx) <= 0 || 
       EVP_PKEY_fromdata(ctx, evp_pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0)
    {
        openssl_get_error();
        OSSL_PARAM_free(params);
        OSSL_PARAM_BLD_free(params_build);
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(params_build);
    EVP_PKEY_CTX_free(ctx);

    return 1;
}

int generate_secret_key_ecdh(EVP_PKEY* pkey, BIGNUM** shared_key, BIGNUM** pub_value_x, BIGNUM** pub_value_y)
{
    EVP_PKEY* peer_pub_key;
    unsigned int outlen;
    unsigned char *skey;
    size_t skeylen;

    if(!generate_ecdh_from_points(&peer_pub_key, pub_value_x, pub_value_y))
    {
        return 0;
    }

    // const EC_KEY *eckey = EVP_PKEY_get0_EC_KEY(peer_pub_key);
    // if (!eckey) {
    //     fprintf(stderr, "Error: Failed to get EC_KEY from EVP_PKEY.\n");
    //     return;
    // }

    // const EC_GROUP *group = EC_KEY_get0_group(eckey);
    // if (!group) {
    //     fprintf(stderr, "Error: Failed to get EC_GROUP from EC_KEY.\n");
    //     return;
    // }

    // const EC_POINT *pub_key = EC_KEY_get0_public_key(eckey);
    // if (!pub_key) {
    //     fprintf(stderr, "Error: Public key point is missing.\n");
    //     return;
    // }

    // BIGNUM *x = BN_new();
    // BIGNUM *y = BN_new();

    // if (!EC_POINT_get_affine_coordinates_GFp(group, pub_key, x, y, NULL)) {
    //     fprintf(stderr, "Error: Failed to get affine coordinates.\n");
    //     BN_free(x);
    //     BN_free(y);
    //     return;
    // }

    // printf("Public Key (x): ");
    // BN_print_fp(stdout, x);
    // printf("\n");

    // printf("Public Key (y): ");
    // BN_print_fp(stdout, y);
    // printf("\n");

    // BN_free(x);
    // BN_free(y);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (ctx == NULL) {
        LOG(COMMON_LOG, "Failed to create EVP_PKEY_CTX\n");
        return 0;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) 
    {
        LOG(COMMON_LOG, "Failed to initialize key derivation\n");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    if (EVP_PKEY_derive_set_peer(ctx, peer_pub_key) <= 0) 
    {
        LOG(COMMON_LOG, "Failed to set peer key\n");
        openssl_get_error();
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

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

    BN_bin2bn(skey, skeylen, *shared_key);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    OPENSSL_free(skey);

    return 1;
}

#endif




