#include <stdio.h>
#include "secure/rsa.h"
#include "common/common.h"
#include "secure/secure.h"
#include "common/file.h"
#include <string.h>
#include <time.h>
#include <openssl/bn.h>
#include "common/packet.h"
#include "log/ftplog.h"
#include "secure/kex.h"
#include <openssl/param_build.h>

#ifdef OPENSSL_3
#include <openssl/evp.h>
#include <openssl/core_names.h>
#endif

int public_key_authentication(control_channel* channel, int evolution)
{
    switch (evolution)
    {
    case 0:
    {

#ifdef OPENSSL_1
        RSA* rsa_private_key = NULL;
#elif OPENSSL_3
        EVP_PKEY* pkey = NULL; //EVP_RSA_gen(KEY_SIZE);
#endif

        BIGNUM *challenge, *recv_challenge, *decrypt_challenge;

        challenge = BN_new(); 
        decrypt_challenge = BN_new();
        recv_challenge = BN_new();

        // Send the RSA public key to endpoint
        channel_send_public_key(channel, public_RSAkey_file);

        if(control_channel_read_expect(channel, FTP_ASYM_AUTHEN) <= 0)
        {
            LOG(SERVER_LOG, "Failed receive challenge\n");
            return 0;
        }

        control_channel_get_bignum(&recv_challenge, channel);

#ifdef OPENSSL_1
        load_private_rsa_key(&rsa_private_key, private_RSAkey_file);
        rsa_pub_decrypt(rsa_private_key, &recv_challenge, &decrypt_challenge);
#elif OPENSSL_3
        load_private_rsa_key(&pkey, private_RSAkey_file);
        // PEM_write_PrivateKey(stdout, pkey, NULL, NULL, 0, NULL, NULL);
        rsa_pub_decrypt(pkey, &recv_challenge, &decrypt_challenge);
#endif
        // check if the decryption working
        if (!BN_cmp(recv_challenge, decrypt_challenge))
        {
            LOG(SERVER_LOG, "Failed decryption\n");
            return 0;
        }

        // printf("sig encrypted:\n");
        // BN_print_fp(stdout, recv_challenge);
        // printf("\n");
        // printf("\ndecrypt_challenge:\n");
        // BN_print_fp(stdout, decrypt_challenge);
        // printf("\n");
        
        control_channel_append_ftp_type(FTP_ASYM_AUTHEN, channel);
        control_channel_append_bignum(&decrypt_challenge, channel);
        control_channel_send_wait(channel);

        if(control_channel_read_expect(channel, FTP_PASS_AUTHEN) <= 0)
        {
            LOG(SERVER_LOG, "Pub key authentication failed\n");
            return 0;
        }

        BN_clear(challenge);
        BN_clear(recv_challenge);
        BN_clear(decrypt_challenge);

#ifdef OPENSSL_1
        RSA_free(rsa_private_key);
#elif OPENSSL_3
        EVP_PKEY_free(pkey);
#endif
        break;
    }

    case 1 :
    {
        BIGNUM* challenge, *decrypt_challenge, *sig, *recv_challenge;

#ifdef OPENSSL_1
        RSA *pub_key = RSA_new();
#elif OPENSSL_3
        EVP_PKEY* pkey = NULL; //EVP_PKEY_new(); //EVP_RSA_gen(KEY_SIZE);
#endif

        challenge = BN_new();
        decrypt_challenge = BN_new();
        recv_challenge = BN_new();
        sig = BN_new();

        if (!BN_rand(challenge, KEY_SIZE - (RSA_PKCS1_PADDING_SIZE  << 3), 0, 0)) 
        {
            LOG(SERVER_LOG, "Error generating random number\n");
            return 0;
        }

        // printf("\nchallenge org:\n");
        // BN_print_fp(stdout, challenge);

#ifdef OPENSSL_1
        // encrypt data 
        channel_recv_public_key(channel, &pub_key, NULL);
        rsa_pub_encrypt(pub_key, &challenge, &sig);
#elif OPENSSL_3
        channel_recv_public_key(channel, NULL, &pkey);
        // PEM_write_PUBKEY(stdout, pkey);
        rsa_pub_encrypt(pkey, &challenge, &sig);
#endif

        // check if the encryption working
        if (!BN_cmp(challenge, sig))
        {
            LOG(SERVER_LOG, "Failed encryption\n");
            return 0;
        }

        // char *hex_str = BN_bn2hex(sig);
        // printf("BIGNUM (hex): %s\n", hex_str);

        // send the challenge to endpoint
        control_channel_append_ftp_type(FTP_ASYM_AUTHEN, channel);
        control_channel_append_bignum(&sig, channel );
        control_channel_send_wait(channel);

        if(control_channel_read_expect(channel, FTP_ASYM_AUTHEN) <= 0)
        {
            LOG(SERVER_LOG, "Pub key authentication failed\n");
            return 0;
        }

        // LOG(1, "RUNNING HERE 3\n");
        control_channel_get_bignum(&recv_challenge, channel);

        // printf("sig encrypted:\n");
        // BN_print_fp(stdout, sig);
        // printf("\n");
        // printf("\nrecv_challenge decrypted:\n");
        // BN_print_fp(stdout, recv_challenge);
        // printf("\n");
        // printf("\nchallenge org:\n");
        // BN_print_fp(stdout, challenge);

        if(BN_cmp(recv_challenge, challenge) != 0)
        {
            control_channel_append_ftp_type(FTP_FAIL_AUTHEN, channel);
            control_channel_send_wait(channel);
            LOG(SERVER_LOG, "%s", "Pub_key authentication failed\n");

            return 0;
        }

        control_channel_append_ftp_type(FTP_PASS_AUTHEN, channel);
        control_channel_send_wait(channel);

        BN_clear(challenge);
        BN_clear(decrypt_challenge);

#ifdef OPENSSL_1
        RSA_free(pub_key);
#elif OPENSSL_3
        EVP_PKEY_free(pkey);
#endif

        break;
    }
        
    default:
        LOG(SERVER_LOG, "Unknown choice evolution\n");
        break;
    }

    return 1;
}

int channel_send_public_key(control_channel* channel, char path[])
{
    BIGNUM *e, *n;

#ifdef OPENSSL_3
    EVP_PKEY* pkey;
#elif` OPENSSL_1
    RSA* pub_key;
#endif

#ifdef OPENSSL_1
    load_rsa_auth_key(&pub_key, path);
    RSA_get0_key(pub_key, &n, &e, NULL );

#elif OPENSSL_3
    e = BN_new();
    n = BN_new();
    load_rsa_auth_key(&pkey, path);
    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n) || 
        !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e)) 
    {
        unsigned long err_code = ERR_get_error();
        if (err_code) 
        {
            char err_buf[120];
            ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
            LOG(SERVER_LOG, "EVP_PKEY_get_bn_param: %s\n",  err_buf);
            fprintf(stderr, "Error: %s\n", err_buf);
        }
        return 0;
    }

    EVP_PKEY_free(pkey);
#endif

    control_channel_append_ftp_type(FTP_PUB_KEY_SEND, channel);
    control_channel_append_bignum(&e, channel);
    control_channel_append_bignum(&n, channel);
    control_channel_send_wait(channel);
    
#ifdef OPENSSL_1
    RSA_free(pub_key);
#endif

    return 1;
}

int channel_recv_public_key(control_channel* channel, RSA** pub_key, EVP_PKEY **pkey)
{
    BIGNUM *pub_key_e = NULL, *pub_key_n = NULL;

    if(!control_channel_read_expect(channel, FTP_PUB_KEY_SEND))
    {
        LOG(COMMON_LOG, "Did not received rsa pub key\n");
        return 0;
    }

    pub_key_e = BN_new();
    pub_key_n = BN_new();

    if( control_channel_get_bignum(&pub_key_e, channel) < 0 || 
        control_channel_get_bignum(&pub_key_n, channel) < 0)
    {
        BN_clear(pub_key_e);
        BN_clear(pub_key_n);
        LOG(COMMON_LOG, "Failed to recieve rsa key\n");
        return 0;
    }

    // printf("RSA modulus (n):\n");
    // BN_print_fp(stdout, pub_key_n);
    // printf("\n");

    // printf("RSA exponent (e):\n");
    // BN_print_fp(stdout, pub_key_e);
    // printf("\n");
#ifdef OPENSSL_1
    RSA_set0_key(*pub_key ,pub_key_n, pub_key_e, NULL);
#elif OPENSSL_3

    // Seems like the approach assigning module n and e directly into 
    // EVP_PKEY_RSA does not work. 

    // if (EVP_PKEY_id(*pkey) != EVP_PKEY_RSA) {
    //     LOG(SERVER_LOG, "EVP_PKEY is not RSA type\n");
    //     return 0;
    // }

    // if(!EVP_PKEY_set_bn_param(*pkey, OSSL_PKEY_PARAM_RSA_N, pub_key_n) || 
    //    !EVP_PKEY_set_bn_param(*pkey, OSSL_PKEY_PARAM_RSA_E, pub_key_e))
    // {
    //     BN_free(pub_key_n);
    //     BN_free(pub_key_e);
    //     LOG(1, "Fail\n");
    //     unsigned long err_code = ERR_get_error();
    //     if (err_code) 
    //     {
    //         char err_buf[120];
    //         ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
    //         fprintf(stderr, "Error: %s\n", err_buf);
    //     }

    //     return 0;
    // }

    // Function is deprecated in openssl 3. Switch to new approach
    // LOG(1, "RUNNNING HEARE 10\n");    
    // EVP_PKEY_assign_RSA(*pkey, *pub_key);

    OSSL_PARAM_BLD *params_build = OSSL_PARAM_BLD_new();
    if ( !OSSL_PARAM_BLD_push_BN(params_build, "n", pub_key_n) ) 
    {
        LOG(SERVER_LOG, "Error: failed to push modulus into param build.\n");
        return 0;
    }
    if ( !OSSL_PARAM_BLD_push_BN(params_build, "e", pub_key_e) ) 
    {
        LOG(SERVER_LOG, "Error: failed to push exponent into param build.\n");
        return 0;
    }
    if ( !OSSL_PARAM_BLD_push_BN(params_build, "d", NULL) ) 
    {
        LOG(SERVER_LOG, "Error: failed to push NULL into param build.\n");
        return 0;
    }
    OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(params_build);
    if ( params == NULL ) 
    {
        LOG(SERVER_LOG, "Error: failed to construct params from build.\n");
        return 0;
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    *pkey = NULL;

    if(ctx == NULL || 
       EVP_PKEY_fromdata_init(ctx) <= 0 || 
       EVP_PKEY_fromdata(ctx, pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0)
    {
        unsigned long err_code = ERR_get_error();
        if (err_code) 
        {
            char err_buf[120];
            ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
            fprintf(stderr, "Error: %s\n", err_buf);
            LOG(SERVER_LOG, "Failure : %s\n", err_buf);
        }
        return 0;
    }

    // Don't make a stupid mistake of freeing this 
    // Only clean these after done with public key
    // BN_free(pub_key_n);
    // BN_free(pub_key_e);

    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(params_build);
    EVP_PKEY_CTX_free(ctx);
#endif    

    return 1;
}

int channel_generate_shared_key(control_channel* channel, cipher_context* ctx)
{
#ifdef OPENSSL_1
    DH* dh = dh_creation();
#elif OPENSSL_3
    EVP_PKEY* pkey = EVP_PKEY_DH_init();
#endif
    BIGNUM* pub;
    BIGNUM* perr_pub;

    pub = NULL; 
    perr_pub = BN_new();

#ifdef OPENSSL_1
    if(!generate_keys(dh))
    {
        LOG(SERVER_LOG, "Failed to generate public keys\n");
        return 0;
    }
#endif

    // Sending the public key over to the endpoint
#ifdef OPENSSL_1
    pub = DH_get0_pub_key(dh);
#elif OPENSSL_3
    // BN_print_fp(stdout, pub);
    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, &pub);
    // BN_print_fp(stdout, pub);
#endif
    control_channel_append_bignum(&pub, channel);
    control_channel_append_ftp_type(FTP_PUB_KEX_SEND, channel);
    control_channel_send(channel);
    // Get the public key from endpoint
    if(!control_channel_read_expect(channel, FTP_PUB_KEX_SEND))
    {
        LOG(SERVER_LOG, "Failed receive public key from endpoint\n");
        return 0;
    }

    control_channel_get_bignum(&perr_pub, channel);

#ifdef OPENSSL_1
    if(!generate_secret_key(dh, &ctx->key, &perr_pub))
#elif OPENSSL_3
    if(!generate_secret_key(pkey, &ctx->key, &perr_pub))
#endif
    {
        LOG(SERVER_LOG, "Failed to compute shared secret key\n");
        return 0;
    }

    return 1;
}