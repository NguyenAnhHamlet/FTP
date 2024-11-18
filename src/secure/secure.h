#ifndef __SECURE__
#define __SECURE__ 

#include <stdio.h>
#include "rsa.h"
#include "common/buffer.h"
#include "common/channel.h"

#define PUB_AUTHEN_SUCCESS  "pub authen success"
#define PUB_AUTHEN_FAIL     "pub authen fail"
#define CHALLENGE_BITS      256

int public_key_authentication(control_channel* channel, int evolution);

int channel_send_public_key(control_channel* channel, char path[]);

int channel_recv_public_key(control_channel* channel, RSA** pub_key, EVP_PKEY **pkey);

int channel_generate_shared_key(control_channel* channel, cipher_context* ctx);

#endif