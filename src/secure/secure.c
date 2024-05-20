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

int public_key_Authentication(Asym_Infos* as_infos)
{
    switch (as_infos->conn)
    {
    case CLIENT:
    {
        // determine the host key algorithm to use
        if(HostKey(as_infos) == Faillure) errorLog("Could not agree and use host key algorithm\n");

        char challenge[CHALLENGE_LENGTH];
        char sig[BUF_LEN];
        size_t sig_length;

        switch (as_infos->as_type)
        {
        case _ECDSA:
        {
            EDCSA_key_pair *ECDSA;

            // Send the ECDSA public key to server
            send_file(as_infos->setupSocket,BUF_LEN,public_ECDSAkey_file);

            // generate the challenge
            generateChallenge(challenge);
            
            // sign the challenge
            read_private_key(ECDSA, private_ECDSAkey_file);
            sign_Challenge(ECDSA, challenge, sizeof(challenge), sig, &sig_length);

            // send the chalenge and the signature to server
            send_msg(as_infos->setupSocket,CHALLENGE_LENGTH,challenge);
            send_msg(as_infos->setupSocket, sig_length, sig);

            break;

        }

        
        case _RSA:
        {   
            RSA *rsa;

            // Send the ECDSA public key to server
            send_file(as_infos->setupSocket,BUF_LEN,public_RSAkey_file);

            // generate the challenge
            generateChallenge(challenge);
            
            // sign the challenge
            read_privateRSA_key(rsa, private_RSAkey_file);
            sign_RSAChallenge(rsa, challenge, sizeof(challenge), sig, &sig_length);

            // send the challenge to server
            send_msg(as_infos->setupSocket,CHALLENGE_LENGTH,challenge);
            send_msg(as_infos->setupSocket, sig_length, sig);

            break;
        }
            
        
        default:
        {
            errorLog("There is no such key\n");
            break;
        }
        }

    }
        
    
    case SERVER:
    {
        // determine the host key algorithm to use
        if(HostKey(as_infos) == Faillure) errorLog("Could not agree and use host key algorithm\n");

        char key[BUF_LEN];
        char res[BUF_LEN];
        char challenge[CHALLENGE_LENGTH];
        char sig[BUF_LEN];
        size_t sig_length;

        switch (as_infos->as_type)
        {
        case _ECDSA:
        {
            EDCSA_key_pair *ECDSA;

            // receive the public key of client
            recv_msg(as_infos->setupSocket, BUF_LEN, key);
            BIO *bio = BIO_new_mem_buf(key, -1);
            ECDSA->eckey = PEM_read_bio_EC_PUBKEY(bio, NULL, NULL, NULL);

            // receive the challenge and the signature
            recv_msg(as_infos->setupSocket, CHALLENGE_LENGTH, challenge);
            recv_msg(as_infos->setupSocket, BUF_LEN, sig);

            // use that public key to verify the challenge
            // reject/accept the connection by opening a new port 
            // for data transfer

            if(verify_challenge(ECDSA,challenge,sizeof(challenge),sig,sig_length) <= 0)
            {
                strcpy(res, PUB_AUTHEN_FAIL);
                send_msg(as_infos,BUF_LEN, res);
                close(as_infos->setupSocket);
                return Faillure;
            }
            else 
            {
                strcpy(res, PUB_AUTHEN_SUCCESS);
                send_msg(as_infos,BUF_LEN, res);
            }

            BIO_free(bio);

            break;

        }
        
        case _RSA:
        {
            RSA *rsa;

            // receive the public key of client
            recv_msg(as_infos->setupSocket, BUF_LEN, key);
            BIO *bio = BIO_new_mem_buf(key, -1);
            rsa = PEM_read_bio_EC_PUBKEY(bio, NULL, NULL, NULL);

            // receive the challenge and the signature
            recv_msg(as_infos->setupSocket, CHALLENGE_LENGTH, challenge);
            recv_msg(as_infos->setupSocket, BUF_LEN, sig);

            // use that public key to verify the challenge
            // reject/accept the connection by opening a new port 
            // for data transfer

            if(verify_RSAchallenge(rsa,challenge,sizeof(challenge),sig,sig_length) <= 0)
            {
                strcpy(res, PUB_AUTHEN_FAIL);
                send_msg(as_infos,BUF_LEN, res);
                close(as_infos->setupSocket);
                errorLog("Authentication failed\n");
            }
            else 
            {
                strcpy(res, PUB_AUTHEN_SUCCESS);
                send_msg(as_infos,BUF_LEN, res);
            }

            BIO_free(bio);

            break;
        }

        
        default:
        {
            errorLog("There is no such key\n");
            break;
        }
        }
    }


    default:
    {
        // something wrong happened, error handle
        errorLog("No such type of endpoint\n");
        break;
    }
    }

    return Success;
}

int HostKey(Asym_Infos* as_infos)
{
    // send to endpoint the list of available hostkey algo
    char bufSend[256];
    char bufRecv[256];
    memset(bufSend,'\0',sizeof(bufSend));
    memset(bufRecv,'\0',sizeof(bufRecv));

    // create message
    strcpy(bufSend,"Hostkey:");

    // check for pair key 
    int rsa = !notExist(private_RSAkey_file) | !notExist(public_RSAkey_file);
    int ecdsa = !notExist(private_ECDSAkey_file) | !notExist(public_ECDSAkey_file);

    if(!(rsa | ecdsa)) return Faillure;

    if(rsa) strcat(bufSend,":rsa");
    

    if(ecdsa) strcat(bufSend,":ecdsa");
    
    // condition sastified, send message to server
    send_msg(as_infos->setupSocket,BUF_LEN,bufSend);

    // receive the message from server 
    recv_msg(as_infos->setupSocket,BUF_LEN,bufRecv);

    int matchRSA = rsa & (strstr(":rsa", bufRecv) ? 1 : 0);
    int matchECDSA = ecdsa & (strstr(":ecdsa", bufRecv) ? 1 : 0);

    if(matchRSA | matchECDSA) return Faillure;

    if(matchECDSA) 
        as_infos->as_type = _ECDSA;
    else if(matchRSA)
        as_infos->as_type = _RSA;
    else 
        return Faillure;
    
    return Success;
}

void generateChallenge(char challenge[])
{
    srand(time(NULL));

    for (size_t i = 0; i < CHALLENGE_LENGTH - 1 ; ++i) 
    {
        challenge[i] = tochar(rand() % 62);
    }

    challenge[CHALLENGE_LENGTH] = '\0';
}