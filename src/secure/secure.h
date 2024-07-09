#ifndef __SECURE__
#define __SECURE__ 

#include <stdio.h>
#include "edcsa.h"
#include "hmac.h"
#include "rsa.h"
#include "buffer.h"
#include "channel.h"

#define PUB_AUTHEN_SUCCESS  "pub authen success"
#define PUB_AUTHEN_FAIL     "pub authen fail"

int public_key_authentication(control_channel* channel, int evolution);

int channel_send_public_key(control_channel* channel, char path[]);

int channel_recv_public_key(control_channel* channel, RSA* pub_key);

#endif