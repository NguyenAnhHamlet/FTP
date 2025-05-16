#ifndef __SECURE__
#define __SECURE__ 

#include <stdio.h>
#include "rsa.h"
#include "common/buffer.h"
#include "common/channel.h"


#define KNOW_HOSTS "/etc/ftp/know_hosts"

enum finger_print_opcode
{
    FINGER_PRINT_SAVED_FAILED,
    FINGER_PRINT_SAVED_SUCCEED,
    FINGER_PRINT_EXITS,
};

// negotiate and return associated public key type
// pkeyaccept_avail is a pointer points to an array of unsined int 
// that represents the available public key of this side 
int pkey_negotiate(control_channel* channel, unsigned int pkeyaccept_avail, endpoint_type type);

// RSA
int public_key_authentication_rsa(control_channel* channel, int evolution);
int channel_send_public_key_rsa(control_channel* channel, char path[]);
int channel_recv_public_key_rsa(control_channel* channel, RSA** pub_key, EVP_PKEY **pkey);

// ED25519
int public_key_authentication_ed25519(control_channel* channel, int evolution);
int channel_send_public_key_ed25519(control_channel* channel, char path[]);
int channel_recv_public_key_ed25519(control_channel* channel, EVP_PKEY **pkey);

// abstract 
// user can use those function above seperately or use this with pkeyaccept_avail
int public_key_authentication(control_channel* channel, int evolution, 
                              unsigned int pkeyaccept_avail);

// Diffie-Hellman

// kex key negotiation
int kexkey_negotiate(control_channel* channel, unsigned int kexkeyaccept_avail, endpoint_type type);

// DH 
int channel_generate_shared_key_dh(control_channel* channel, cipher_context* ctx);

// ECDH 
int channel_generate_shared_key_ecdh(control_channel* channel, cipher_context* ctx);

// abstract wrapper function
int channel_generate_shared_key(control_channel* channel, cipher_context* ctx, 
                                unsigned int kexkeyaccept_avail);

// finger-print
int channel_verify_finger_print_rsa(control_channel* channel, endpoint_type type);
int channel_verify_finger_print_ed25519(control_channel* channel, endpoint_type type);
int channel_verify_finger_print(control_channel* channel, endpoint_type type, 
                                unsigned int pkeyaccept);

// TODO : 
// Allow using public authen to bypass password authen 

#endif