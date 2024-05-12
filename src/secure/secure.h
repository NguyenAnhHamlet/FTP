#ifndef __SECURE__
#define __SECURE__ 

#include <stdio.h>
#include "edcsa.h"
#include "hmac.h"
#include "rsa.h"

#define CHALLENGE_LENGTH    129
#define PUB_AUTHEN_SUCCESS  "pub authen success"
#define PUB_AUTHEN_FAIL     "pub authen fail"

typedef enum Asym_Type 
{
    _ECDSA,
    _RSA
} Asym_Type ;

typedef struct Asym_Infos
{
    Asym_Type as_type;
    Conn_Type conn;
    unsigned int setupSocket;
    char Key_File[256];
} Asym_Infos;


// execute public key authentication
// return Success if the authentication is done 
// properly
// return Failure if the authentication failed
// the return value of this function indicate 
// whether the connection can be keeped or not 
// will be handled by another function
int public_key_Authentication(Asym_Infos* as_infos);

// determine which public key algorithm to use between client and server
int HostKey(Asym_Infos* as_infos);

void generateChallenge(char challenge[]);

#endif