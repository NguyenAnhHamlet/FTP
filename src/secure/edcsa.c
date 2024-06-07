#include "edcsa.h"
#include "file.h"
#include <string.h>
#include "common.h"

void set_EDCSA_key_pair(EDCSA_key_pair* ECDSA, EC_GROUP* ecgroup,
                        EC_KEY *eckey)
{
    ECDSA->ecgroup = ecgroup;
    ECDSA->eckey = eckey;
}

void generate_ECDSA_KEYPAIR(EDCSA_key_pair* ECDSA)
{
    // Set EC group for the key
    if (EC_KEY_set_group(ECDSA->eckey, ECDSA->ecgroup) != 1) 
    {
        ERR_print_errors_fp(stderr);
        EC_GROUP_free(ECDSA->ecgroup);
        EC_KEY_free(ECDSA->eckey);
        return ;
    }

    // Generate key pair
    if (!EC_KEY_generate_key(ECDSA->eckey)) 
    {
        ERR_print_errors_fp(stderr);
        EC_GROUP_free(ECDSA->ecgroup);
        EC_KEY_free(ECDSA->eckey);
        return ;
    }


}

void save_public_key(EDCSA_key_pair* ECDSA, char path[])
{
    EVP_PKEY *keypair = EVP_PKEY_new();

    if(!keypair) fatal("Couldn't create keypair");

    if(!EVP_PKEY_assign_EC_KEY(keypair, ECDSA->eckey))
        fatal("Couldn't assign keypair");

    FILE *fp = fopen(path, "a");
    
    if(!fp) fatal("Couldn't open file");
    

    if (!PEM_write_EC_PUBKEY(fp, keypair)) 
        fatal("Error writing public key to file");

    fclose(fp);
    EVP_PKEY_free(keypair);

}

void save_private_key(EDCSA_key_pair* ECDSA, char path[])
{
    EVP_PKEY *keypair = EVP_PKEY_new();

    if(!keypair) fatal("Couldn't create keypair");

    if(!EVP_PKEY_assign_EC_KEY(keypair, ECDSA->eckey))
        fatal("Couldn't assign keypair");

    FILE *fp = fopen(path, "a");

    if(!fp) fatal("Couldn't open file");

    if(!PEM_write_ECPrivateKey(fp, keypair,NULL, NULL, 0, NULL, NULL))
        fatal("Error writing private key to file");

    fclose(fp);
    EVP_PKEY_free(keypair);
}

int edcsa_pub_encrypt( EDCSA_key_pair* ECDSA, BIGNUM *challenge, 
                    int challenge_len, BIGNUM *signature, 
                    size_t *signature_len)
{
   EVP_PKEY_CTX *ctx;
    char *inbuf, *outbuf;
	int len, ilen, olen;

    ctx = EVP_PKEY_CTX_new();
    size_t sig_size = ECDSA_size(ECDSA->eckey);

    olen = BN_num_bytes(ECDSA->eckey);          // might be an issue
	outbuf = xmalloc(olen);

	ilen = BN_num_bytes(in);
	inbuf = xmalloc(ilen);
	BN_bn2binpad(signature, inbuf, ilen);

    if (EVP_PKEY_encrypt_init_ex(ctx, NULL, NULL, ECDSA->eckey) != 1) 
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

int ecdsa_priv_decrypt(EDCSA_key_pair* ECDSA, BIGNUM *challenge, 
                    int challenge_len, BIGNUM *signature, 
                    size_t* signature_len)
{
    EVP_PKEY_CTX *ctx;
	char *inbuf, *outbuf;
	int len, ilen, olen;

    ctx = EVP_PKEY_CTX_new();

	olen = BN_num_bytes(ECDSA->eckey);                  // might be an issue
	outbuf = (char*)malloc(olen);

	ilen = BN_num_bytes(signature);
	inbuf = (char*)malloc(ilen);
    BN_bn2binpad(signature, inbuf, ilen);

    if (EVP_PKEY_decrypt_init_ex(ctx, NULL, NULL, ECDSA->eckey) != 1) 
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

int read_auth_key(EDCSA_key_pair* ECDSA, char path[], char* pattern)
{
    FILE* pipe;
    if(!has_Pattern(path,pattern,pipe))
    {
        return Faillure;
    }
    
    ECDSA->eckey = PEM_read_PUBKEY(pipe,NULL,NULL,NULL);

    if(!ECDSA->eckey) fatal("Could not read public key\n");

    pclose(pipe);

    return Success;

}

int read_private_key(EDCSA_key_pair* ECDSA, char path[])
{
    if(notExist(path))
        return Faillure;

    FILE* fp = fopen(path, "rb");
    ECDSA->eckey = PEM_read_PrivateKey(fp,NULL,NULL,NULL);  

    if(!ECDSA->eckey) fatal("Could not read private key\n");

    return Success;
}