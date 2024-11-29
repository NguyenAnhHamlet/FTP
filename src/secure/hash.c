#include "openssl/sha.h"
#include "hash.h"
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

void sha256(char* in, int inlen, char* out, int outlen )
{
#ifdef OPENSSL_1 
    outlen = SHA256_DIGEST_LENGTH;
    out = (char*) malloc(SHA256_DIGEST_LENGTH);
    SHA256_CTX sh256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, in, inlen);
    SHA256_Final(out, &sha256);

#elif OPENSSL_3
    out = (char*) malloc(EVP_MAX_MD_SIZE);
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

    if (!EVP_DigestFinal_ex(mdCtx, out, &outlen))
    {
        printf("Message digest finalization failed.\n");
        EVP_MD_CTX_free(mdCtx);
        exit(EXIT_FAILURE);
    }
    EVP_MD_CTX_free(mdCtx);

#endif
}