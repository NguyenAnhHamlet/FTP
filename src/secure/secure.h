#ifndef __SECURE__
#define __SECURE__ 

#include <stdio.h>
#include "rsa.h"
#include "common/buffer.h"
#include "common/channel.h"

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
int channel_generate_shared_key(control_channel* channel, cipher_context* ctx);

#endif