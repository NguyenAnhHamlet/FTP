#include <stdio.h>
#include "edcsa.h"
#include "hmac.h"
#include "rsa.h"
#include "common.h"
#include "secure.h"
#include "file.h"
#include <string.h>
#include "send.h"
#include "receive.h"
#include <time.h>
#include <openssl/bn.h>
#include "packet.h"

int public_key_authentication(control_channel* channel, int evolution)
{
    switch (evolution)
    {
    case 0:
    {
        BIGNUM *challenge, *sig, recv_challenge;
        challenge = BN_new(); 
        sig = BN_new();  
        RSA *private_key;

        size_t sig_length;

        // Send the RSA public key to endpoint
        control_channel_append_ftp_type(FTP_PUB_KEY_SEND, channel);
        channel_send_public_key(channel, public_RSAkey_file);

        if(control_channel_read_expect(channel, FTP_ACK) != 1)
        {
            LOG("Server fails to receive RSA pub_key");
            return 0;
        }
        
        // encrypt the challenge
        load_private_rsa_key(private_key, private_RSAkey_file);
        rsa_pub_encrypt(private_key, challenge, sizeof(challenge), sig, &sig_length);

        control_channel_append_ftp_type(FTP_ASYM_AUTHEN, channel);
        control_channel_append_bignum(sig, channel );

        // send the challenge to endpoint
        control_channel_send_wait(channel);

        if(control_channel_read_expect(channel, FTP_ACK) != 1)
        {
            LOG("Server fails to receive RSA challenge");
            return 0;
        }

        if(control_channel_read_expect(channel, FTP_ASYM_AUTHEN))
        {
            control_channel_get_bignum(recv_challenge, channel);

            if(!BN_cmp(recv_challenge, challenge))
                fatal("%s", "Pub_key authentication failed\n");
        }

        BN_clear(challenge);
        BN_clear(recv_challenge);
        BN_clear(sig);
        RSA_free(private_key);

        break;
    }

    case 1 :
    {
        RSA *pub_key;
        BIGNUM* challenge, *decrypt_challenge;

        if(control_channel_read_expect(channel, FTP_PUB_KEY_SEND) <= 0)
        {
            LOG("Faild receive public key\n");
            return 0;
        }

        channel_recv_public_key(channel, pub_key);
        
<<<<<<< HEAD
        control_channel_append_ftp_type(FTP_ACK, channel);
=======
        control_channel_append_int(FTP_ACK, channel);
>>>>>>> 14a728ce950b1f1d31e5c2ca3e3777f82f231bd5
        control_channel_send(channel);

        if(control_channel_read_expect(channel, FTP_ASYM_AUTHEN) <= 0)
        {
            LOG("Failed receive challange\n");
            return 0;
        }

        control_channel_get_bignum(challenge, channel);
        rsa_pub_decrypt(pub_key, challenge, BN_num_bits(challenge),
                        decrypt_challenge, BN_num_bits(decrypt_challenge))

<<<<<<< HEAD
        control_channel_append_ftp_type(FTP_ASYM_AUTHEN, channel);
=======
        control_channel_append_int(FTP_ASYM_AUTHEN);
>>>>>>> 14a728ce950b1f1d31e5c2ca3e3777f82f231bd5
        control_channel_append_bignum(decrypt_challenge, channel);

        control_channel_send(channel);

        BN_clear(challenge);
        BN_clear(decrypt_challenge);
        RSA_free(pub_key);

        break;
    }
        
    default:
        LOG("Unknown choice evolution\n");
        break;
    }

    return 1;
}

int channel_send_public_key(control_channel* channel, char path[])
{
    RSA* pub_key;
    BIGNUM *pub_key_e, *pub_key_n;

    load_rsa_auth_key(pub_key, path);

    pub_key_e = BN_new();
    pub_key_n = BN_new();

    BN_copy(pub_key->e, pub_key_e);
    BN_copy(pub_key->n, pub_key_n);

    packet_init(channel->data_out, channel->data_out->out_port, 
                FTP_PUB_KEY_SEND, -1, -1 );
    packet_append_bignum(pub_key_e, channel->data_out);
    packet_append_bignum(pub_key_n, channel->data_out);
    packet_send_wait(channel->data_out);

    BN_clear(pub_key_e);
    BN_clear(pub_key_n);
    RSA_free(pub_key);

    return 1;
}

int channel_recv_public_key(control_channel* channel, RSA* pub_key)
{
    BIGNUM *pub_key_e, *pub_key_n;

    int packet_type = packet_get_int(channel->data_in);

    if(packet_type != FTP_PUB_KEY_SEND)
    {
        channel->data_in->buf -= sizeof(packet_type);
        BN_clear(pub_key_e);
        BN_clear(pub_key_n);
        return -1;
    }
    
    if( packet_get_bignum(pub_key_e, channel->data_in) < 0 || 
        packet_get_bignum(pub_key_n, channel->data_in) < 0)
    {
        BN_clear(pub_key_e);
        BN_clear(pub_key_n);
        return -1;
    }

    BN_copy(pub_key->e, pub_key_e);
    BN_copy(pub_key->n, pub_key_n);
    
    BN_clear(pub_key_e);
    BN_clear(pub_key_n);

    return 1;
}