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
#include <stdarg.h>

#define KEY_TYPE "-k"
#define OVEWRITE "-o"
#define ECDSA_KEY "ecdsa"
#define RSA_KEY "rsa"

void keygen(int argc, ...);