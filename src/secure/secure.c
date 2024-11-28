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
#include "secure/ed25519.h"

#ifdef OPENSSL_3
#include <openssl/evp.h>
#include <openssl/core_names.h>
#endif

extern void openssl_get_error();

// client initiate the negotiation first by declaring to server which keys it possesses 
// server then check in its own list of available supported key to see if there are 
// at least one match. If there are , the operation shall proceed by server sending 
// back the available key for both to use. If not, send the ABORT 
// If both rsa and ed25519 is available, ed25519 shall be the chosen one
int pkey_negotiate(control_channel* channel, unsigned int pkeyaccept_avail, endpoint_type type)
{
    switch(type)
    {
        case CLIENT:
        {
            // Send the list of available key type to server
            control_channel_append_ftp_type(FTP_PKEY_NEGOTIATE, channel);
            control_channel_append_int(pkeyaccept_avail, channel);
            control_channel_send_wait(channel);

            // get response from server
            if(control_channel_read_expect(channel, ABORT))
            {
                LOG(CLIENT_LOG, "No public key available\n");
                return 0;
            }

            // Now we have the agreed upon public key type 
            return control_channel_get_int(channel);

            break;        
        }

        case SERVER:
        {
            int ret =0;
            // get the list of available pub key from client
            if(!control_channel_read_expect(channel, FTP_PKEY_NEGOTIATE))
            {
                LOG(SERVER_LOG, "Expected %d but got %d instead", FTP_PKEY_NEGOTIATE, 
                    control_channel_get_ftp_type_in(channel));
                return 0;
            }
            int recv_pkeyaccept = control_channel_get_int(channel);
            control_channel_append_ftp_type(FTP_PKEY_NEGOTIATE, channel);
            if(recv_pkeyaccept & ED25519K)
            {
                ret = 1;
                control_channel_append_int(ED25519K, channel);
            }
            else if(recv_pkeyaccept & RSAK)
            {
                ret = 1;
                control_channel_append_int(RSAK, channel);
            }
            else 
            {
                control_channel_append_ftp_type(ABORT, channel);
            }

            control_channel_send_wait(channel);
            return ret;

            break;
        }

        default:
            return 0;
    }
}

int public_key_authentication_rsa(control_channel* channel, int evolution)
{
    switch (evolution)
    {
    case 0:
    {

#ifdef OPENSSL_1
        RSA* rsa_private_key = NULL;
#elif OPENSSL_3
        EVP_PKEY* pkey = NULL; 
#endif

        BIGNUM *challenge, *recv_challenge, *decrypt_challenge;

        challenge = BN_new(); 
        decrypt_challenge = BN_new();
        recv_challenge = BN_new();

        // Send the RSA public key to endpoint
        channel_send_public_key_rsa(channel, public_RSAkey_file);

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
        EVP_PKEY* pkey = NULL; 
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
        channel_recv_public_key_rsa(channel, &pub_key, NULL);
        // TODO 
        // Write public key into "/etc/ftp/know_hosts" with format
        // "host_name keytype keyvalue"
        rsa_pub_encrypt(pub_key, &challenge, &sig);
#elif OPENSSL_3
        channel_recv_public_key_rsa(channel, NULL, &pkey);
        // PEM_write_PUBKEY(stdout, pkey);
        // TODO 
        // Write public key into "/etc/ftp/know_hosts" with format
        // "host_name keytype keyvalue"
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

int channel_send_public_key_rsa(control_channel* channel, char path[])
{
    BIGNUM *e, *n;

#ifdef OPENSSL_3
    EVP_PKEY* pkey;
#elif OPENSSL_1
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

int channel_recv_public_key_rsa(control_channel* channel, RSA** pub_key, EVP_PKEY **pkey)
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
        openssl_get_error();
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

int public_key_authentication_ed25519(control_channel* channel, int evolution)
{
    switch(evolution)
    {
        case 0:
        {
            EVP_PKEY* edpkey = NULL;
            BIGNUM* challenge = BN_new();
            BIGNUM* sign = BN_new();
            // send the public key over the endpoint 
            channel_send_public_key_ed25519(channel, PUBLIC_ED25519);
            
            // Confirm received 
            if(!control_channel_read_expect(channel, FTP_ASYM_AUTHEN))
            {
                LOG(COMMON_LOG, "Fail to received the signature and" 
                    "message by other side\n");
                return 0;
            }

            // generate a random BIGNUM challenge
            if (!BN_rand(challenge, CHALLENGE_LEN, 0, 0)) 
            {
                LOG(SERVER_LOG, "Error generating random number\n");
                return 0;
            }


            // sign operation with private key
            load_private_ed25519_key(&edpkey, PRIVATE_ED25519);
            if(!edpkey)
            {
                LOG(COMMON_LOG, "Fail to load ed25519 private key\n");
                return 0;
            }
            
            ed25519_priv_sign(edpkey, &challenge, &sign);

            if(!BN_cmp(challenge, sign))
            {   
                BN_print_fp(stdout, challenge); printf("\n"); BN_print_fp(stdout, sign);
                LOG(COMMON_LOG, "Fail to sign\n");
                return 0;
            }

            // send signature and challenge to other endpoint
            control_channel_append_ftp_type(FTP_ASYM_AUTHEN, channel);
            control_channel_append_bignum(&challenge, channel);
            control_channel_append_bignum(&sign, channel);
            control_channel_send_wait(channel);

            if(!control_channel_read_expect(channel, SUCCESS))
            {
                LOG(COMMON_LOG, "Expected %d but received %d", 
                    SUCCESS, control_channel_get_ftp_type_in(channel));
                return 0;
            }

            break;
        }

        case 1:
        {
            EVP_PKEY* edpkey = NULL;
            BIGNUM* challenge = BN_new();
            BIGNUM* sign = BN_new();
            // receive the public key from end point
            
            channel_recv_public_key_ed25519(channel, &edpkey);

            // send confirmation 
            control_channel_append_ftp_type(FTP_ASYM_AUTHEN, channel);
            control_channel_send(channel);

            // receive signature and challenge 
            if(!control_channel_read_expect(channel, FTP_ASYM_AUTHEN))
            {
                LOG(1, "Expected %d but received %d", 
                    FTP_ASYM_AUTHEN, control_channel_get_ftp_type_in(channel));
                return 0;
            }

            control_channel_get_bignum(&challenge, channel);
            control_channel_get_bignum(&sign, channel);

            // check the signature with public key
            if(!ed25519_pub_verify(edpkey, &challenge, &sign))
            {
                LOG(COMMON_LOG, "Could not verify the signature\n");
                control_channel_append_ftp_type(ABORT, channel);
                control_channel_send(channel);
                return 0;
            }

            control_channel_append_ftp_type(SUCCESS, channel);
            control_channel_send(channel);
        }
    }

    return 1;
}

int channel_send_public_key_ed25519(control_channel* channel, char path[])
{
    // load the public key from ed25519.pub
    EVP_PKEY* pkey = NULL;
    load_ed25519_auth_key(&pkey, PUBLIC_ED25519);

    if(!pkey)
    {
        LOG(COMMON_LOG, "fail to load in public ed25519\n");
        return 0;
    }

    LOG(1, "RUNNING 10\n");

    size_t pubkey_len = 0;
    if (!EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &pubkey_len)) 
    {
        ERR_print_errors_fp(stderr);
        return 1;                                                                                                                                   
    }

    unsigned char *pubkey = OPENSSL_malloc(pubkey_len);

    if (!EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, pubkey, pubkey_len, &pubkey_len)) 
    {
        ERR_print_errors_fp(stderr);
        OPENSSL_free(pubkey);
        return 1;
    }

    if (!pubkey) 
    {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    LOG(1, "RUNNING 11\n");

    // send the public ed25519 over 
    control_channel_append_ftp_type(FTP_PUB_KEY_SEND, channel);
    control_channel_append_str(pubkey, channel, pubkey_len);
    control_channel_send_wait(channel);

    // free
    EVP_PKEY_free(pkey);

    return 1;
}

int channel_recv_public_key_ed25519(control_channel* channel, EVP_PKEY **pkey)
{
    char* pubkey = NULL;
    int pubkey_len = 0;
    
    LOG(1, "RUNNING 0\n");

    if(!control_channel_read_expect(channel, FTP_PUB_KEY_SEND))
    {
        LOG(COMMON_LOG, "Expected code value %d but got %d instead\n",
            FTP_PUB_KEX_SEND, control_channel_get_ftp_type_in(channel));
        return 0;
    }

    LOG(1, "RUNNING\n");

    pubkey = (char*) malloc(control_channel_get_data_len_in(channel));
    control_channel_get_str(channel, pubkey, &pubkey_len);

    if(!pubkey)
    {
        LOG(COMMON_LOG, "pubkey NULL\n");
        return 0;
    }

    LOG(1, "RUNNING 2\n");

    OSSL_PARAM_BLD *params_build = OSSL_PARAM_BLD_new();
    if ( !OSSL_PARAM_BLD_push_octet_string(params_build, OSSL_PKEY_PARAM_PUB_KEY, pubkey, pubkey_len)) 
    {
        LOG(COMMON_LOG, "Error: failed to push public value into param build.\n");
        return 0;
    }

    LOG(1, "RUNNING 3\n");

    OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(params_build);
    if ( params == NULL ) 
    {
        LOG(COMMON_LOG, "Error: failed to construct params from build.\n");
        return 0;
    }

    LOG(1, "RUNNING 4\n");

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(NULL, "ED25519", NULL);
    *pkey = NULL;

    if(ctx == NULL || 
       EVP_PKEY_fromdata_init(ctx) <= 0 || 
       EVP_PKEY_fromdata(ctx, pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0)
    {
        openssl_get_error();
        return 0;
    }

    LOG(1, "RUNNING 5\n");

    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(params_build);
    EVP_PKEY_CTX_free(ctx);
}

int public_key_authentication(control_channel* channel, int evolution, 
                                      unsigned int pkeyaccept_avail)
{
    printf("%d\n", pkeyaccept_avail);
    switch(pkeyaccept_avail)
    {
    case ED25519K:
        return public_key_authentication_ed25519(channel, evolution);
    case RSAK:
        return public_key_authentication_rsa(channel, evolution);
    default:
        return 0;
    }
}

//  diffie-hellman
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
    // TODO
    // Load public key of peer from know_hosts  
    // encrypt the DH's pub key with peer's RSA public key before send over 

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
    // TODO 
    // decrypt the perr_pub key with private RSA key

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