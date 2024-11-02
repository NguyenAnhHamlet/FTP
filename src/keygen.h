#include <stdio.h>
#include "secure/rsa.h"
#include "common/common.h"
#include "secure/secure.h"
#include "common/file.h"
#include <string.h>
#include <time.h>
#include <stdarg.h>

#define KEY_TYPE "-k"
#define OVEWRITE "-o"
#define ECDSA_KEY "ecdsa"
#define RSA_KEY "rsa"

void keygen(int argc, ...);