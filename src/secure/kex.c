#include "kex.h"
#include <openssl/bn.h>
#include "log/ftplog.h"
#include <openssl/err.h>

DH* dh_creation()
{
    static char *gen = "2", *group =
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF";

    DH *dh;
    BIGNUM *p, *g, *q, *p_cp;

    p = BN_new();
    g = BN_new();
    p_cp = BN_new();
    q = BN_new();

    dh = DH_new();
    if(!dh) return NULL;

    // convert to BIGNUM value
    if(!BN_hex2bn(&g, gen) || !BN_hex2bn(&p, group) || !BN_hex2bn(&p_cp, group))
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

int generate_pub_keys(DH *dh)
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

