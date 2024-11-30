#include "openssl/sha.h"
#include "hash.h"
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include "log/ftplog.h"

void sha256(char* in, int inlen, char** out, int *outlen )
{
    char* out_sha256 = NULL;
    unsigned int out_sha256_len;

#ifdef OPENSSL_1 
    out_sha256 = SHA256_DIGEST_LENGTH;
    out_sha256_len = (char*) malloc(SHA256_DIGEST_LENGTH);
    SHA256_CTX sh256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, in, inlen);
    SHA256_Final(out_sha256, &sha256);

#elif OPENSSL_3
    out_sha256 = (char*) malloc(EVP_MAX_MD_SIZE);
    EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
    unsigned char *md;
    unsigned int mdLen, i;

    if (!EVP_DigestInit_ex(mdCtx, EVP_sha256(), NULL))
    {
        printf("Message digest initialization failed.\n");
        EVP_MD_CTX_free(mdCtx);
        exit(EXIT_FAILURE);
    }

    // Hashes cnt bytes of data at d into the digest context mdCtx
    if (!EVP_DigestUpdate(mdCtx, in, inlen))
    {
        printf("Message digest update failed.\n");
        EVP_MD_CTX_free(mdCtx);
        exit(EXIT_FAILURE);
    }

    if (!EVP_DigestFinal_ex(mdCtx, out_sha256, &out_sha256_len))
    {
        printf("Message digest finalization failed.\n");
        EVP_MD_CTX_free(mdCtx);
        exit(EXIT_FAILURE);
    }
    EVP_MD_CTX_free(mdCtx);

    LOG(SERVER_LOG, "HERE 4");

#endif

    // convert to human readable format
    *outlen = SHA256_DIGEST_LENGTH << 1;
    *out = (char*) malloc(*outlen);

    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(*out + (i << 1), "%02x", out_sha256[i]);
    }

    out[64] = 0;

}