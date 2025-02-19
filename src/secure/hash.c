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

    LOG(SERVER_LOG, "HERE BEGIN\n");

#ifdef OPENSSL_1 
    SHA256_CTX sha256;
    out_sha256_len = SHA256_DIGEST_LENGTH;
    out_sha256 = (char*) malloc(SHA256_DIGEST_LENGTH);

    LOG(SERVER_LOG, "HERE NOT BLOCK 0\n");

    if(!SHA256_Init(&sha256))
    {
        openssl_get_error();
        free(out_sha256);
        return 0;
    }

    LOG(SERVER_LOG, "HERE NOT BLOCK 1\n");

    if(!SHA256_Update(&sha256, in, inlen))
    {
        openssl_get_error();
        free(out_sha256);
        return 0;
    }

    LOG(SERVER_LOG, "HERE NOT BLOCK 2\n");

    if(!SHA256_Final(out_sha256, &sha256))
    {
        openssl_get_error();
        free(out_sha256);
        return 0;
    }

    LOG(SERVER_LOG, "HERE NOT BLOCK 3\n");

#elif OPENSSL_3
    out_sha256 = (char*) malloc(EVP_MAX_MD_SIZE);
    EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
    unsigned char *md;
    unsigned int mdLen, i;

    if (!EVP_DigestInit_ex(mdCtx, EVP_sha256(), NULL))
    {
        LOG(SERVER_LOG, "Message digest initialization failed.\n");
        EVP_MD_CTX_free(mdCtx);
        openssl_get_error();
        exit(EXIT_FAILURE);
    }

    // Hashes cnt bytes of data at d into the digest context mdCtx
    if (!EVP_DigestUpdate(mdCtx, in, inlen))
    {
        LOG(SERVER_LOG,  "Message digest update failed.\n");
        EVP_MD_CTX_free(mdCtx);
        openssl_get_error();
        exit(EXIT_FAILURE);
    }

    if (!EVP_DigestFinal_ex(mdCtx, out_sha256, &out_sha256_len))
    {
        LOG(SERVER_LOG, "Message digest finalization failed.\n");
        EVP_MD_CTX_free(mdCtx);
        openssl_get_error();
        exit(EXIT_FAILURE);
    }

    EVP_MD_CTX_free(mdCtx);

    LOG(SERVER_LOG, "HERE 4");

#endif

    LOG(SERVER_LOG, "HERE MIDDLE\n");

    // convert to human readable format
    *outlen = SHA256_DIGEST_LENGTH << 1;
    *out = (char*) malloc(*outlen);

    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(*out + (i << 1), "%02x", out_sha256[i]);
    }

    out[64] = 0;

    LOG(SERVER_LOG, "HERE END\n");

}