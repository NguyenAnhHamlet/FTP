#include "kex.h"

DH* dh_creation()
{
    static char *gen = "2", *group =
	    "FFFFFFFF" "FFFFFFFF" "C90FDAA2" "2168C234" "C4C6628B" "80DC1CD1"
	    "29024E08" "8A67CC74" "020BBEA6" "3B139B22" "514A0879" "8E3404DD"
	    "EF9519B3" "CD3A431B" "302B0A6D" "F25F1437" "4FE1356D" "6D51C245"
	    "E485B576" "625E7EC6" "F44C42E9" "A637ED6B" "0BFF5CB6" "F406B7ED"
	    "EE386BFB" "5A899FA5" "AE9F2411" "7C4B1FE6" "49286651" "ECE65381"
	    "FFFFFFFF" "FFFFFFFF";

    DH *dh;
    BIGNUM *p, *g;

    dh = DH_new();
    if(!dh) return NULL;

    // convert to BIGNUM value
    if(!BN_hex2bn(&g, group) || !BN_hex2bn(p, gen))
    {
        DH_free(dh);
        BN_clear_free(p);
        BN_clear_free(g);
        return NULL;
    }

    if (!DH_set0_pqg(dh, p, NULL, g))
    {
        DH_free(dh);
        BN_clear_free(p);
        BN_clear_free(g);
        return NULL;
    }

    return dh;
}

int generate_kex_key(DH *dh)
{
    if(!dh) 
        return 0;

    BIGNUM *p, *g;

    DH_get0_pqg(dh, &p, NULL, &g);

    if(!p || !g ) 
        return 0;
    
    int length = BN_num_bits(p) * 2;

    if(!DH_set_length(dh, length))
        return 0;

    if (DH_generate_key(dh) == 0)
        return 0;

    return 1;
}

int compute_kex_key(DH* dh, BIGNUM* shared_secret, BIGNUM* pub_key)
{
    unsigned char* key;

    if(!DH_compute_key(key, pub_key, dh))
        return 0;
    
    if(!BN_bin2bn(key, sizeof(key), shared_secret))
        return 0;
    
    return 1;
}