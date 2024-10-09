// Client side C program to demonstrate Socket
// programming
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#define PORT 51000

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main(int argc, char const* argv[])
{
    int status, valread, client_fd;
    struct sockaddr_in* serv_addr = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
    char* hello = "Hello from client";
    char buffer[1024] = { 0 };
    if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }

    printf("%d", client_fd);


    serv_addr->sin_family = AF_INET;
    serv_addr->sin_port = htons(PORT);

    // Convert IPv4 and IPv6 addresses from text to binary
    // form
    if (inet_pton(AF_INET, "192.168.1.7", &serv_addr->sin_addr)
        <= 0) {
        printf(
            "\nInvalid address/ Address not supported \n");
        return -1;
    }

    if ((status
         = connect(client_fd, (struct sockaddr*)serv_addr,
                   sizeof(*serv_addr)))
        < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }
    send(client_fd, hello, strlen(hello), 0);
    printf("Hello message sent\n");
    valread = read(client_fd, buffer,
                   1024 - 1); // subtract 1 for the null
                              // terminator at the end
    printf("%s\n", buffer);

    // closing the connected socket
    close(client_fd);
    return 0;
}

static int generate_key(DH *dh)
{
    int ok = 0;
    int generate_new_key = 0;
#ifndef FIPS_MODULE
    unsigned l;
#endif
    BN_CTX *ctx = NULL;
    BIGNUM *pub_key = NULL, *priv_key = NULL;

    if (BN_num_bits(dh->params.p) > OPENSSL_DH_MAX_MODULUS_BITS) {
        ERR_raise(ERR_LIB_DH, DH_R_MODULUS_TOO_LARGE);
        return 0;
    }

    if (dh->params.q != NULL
        && BN_num_bits(dh->params.q) > OPENSSL_DH_MAX_MODULUS_BITS) {
        ERR_raise(ERR_LIB_DH, DH_R_Q_TOO_LARGE);
        return 0;
    }

    if (BN_num_bits(dh->params.p) < DH_MIN_MODULUS_BITS) {
        ERR_raise(ERR_LIB_DH, DH_R_MODULUS_TOO_SMALL);
        return 0;
    }

    ctx = BN_CTX_new_ex(dh->libctx);
    if (ctx == NULL)
        goto err;

    if (dh->priv_key == NULL) {
        priv_key = BN_secure_new();
        if (priv_key == NULL)
            goto err;
        generate_new_key = 1;
    } else {
        priv_key = dh->priv_key;
    }

    if (dh->pub_key == NULL) {
        pub_key = BN_new();
        if (pub_key == NULL)
            goto err;
    } else {
        pub_key = dh->pub_key;
    }
    if (generate_new_key) {
        /* Is it an approved safe prime ?*/
        if (DH_get_nid(dh) != NID_undef) {
            int max_strength =
                    ossl_ifc_ffc_compute_security_bits(BN_num_bits(dh->params.p));

            if (dh->params.q == NULL
                || dh->length > BN_num_bits(dh->params.q))
                goto err;
            /* dh->length = maximum bit length of generated private key */
            if (!ossl_ffc_generate_private_key(ctx, &dh->params, dh->length,
                                               max_strength, priv_key))
                goto err;
        } else {
#ifdef FIPS_MODULE
            if (dh->params.q == NULL)
                goto err;
#else
            if (dh->params.q == NULL) {
                /* secret exponent length, must satisfy 2^(l-1) <= p */
                if (dh->length != 0
                    && dh->length >= BN_num_bits(dh->params.p))
                    goto err;
                l = dh->length ? dh->length : BN_num_bits(dh->params.p) - 1;
                if (!BN_priv_rand_ex(priv_key, l, BN_RAND_TOP_ONE,
                                     BN_RAND_BOTTOM_ANY, 0, ctx))
                    goto err;
                /*
                 * We handle just one known case where g is a quadratic non-residue:
                 * for g = 2: p % 8 == 3
                 */
                if (BN_is_word(dh->params.g, DH_GENERATOR_2)
                    && !BN_is_bit_set(dh->params.p, 2)) {
                    /* clear bit 0, since it won't be a secret anyway */
                    if (!BN_clear_bit(priv_key, 0))
                        goto err;
                }
            } else
#endif
            {
                /* Do a partial check for invalid p, q, g */
                if (!ossl_ffc_params_simple_validate(dh->libctx, &dh->params,
                                                     FFC_PARAM_TYPE_DH, NULL))
                    goto err;
                /*
                 * For FFC FIPS 186-4 keygen
                 * security strength s = 112,
                 * Max Private key size N = len(q)
                 */
                if (!ossl_ffc_generate_private_key(ctx, &dh->params,
                                                   BN_num_bits(dh->params.q),
                                                   MIN_STRENGTH,
                                                   priv_key))
                    goto err;
            }
        }
    }

    if (!ossl_dh_generate_public_key(ctx, dh, priv_key, pub_key))
        goto err;

    dh->pub_key = pub_key;
    dh->priv_key = priv_key;
    dh->dirty_cnt++;
    ok = 1;
 err:
    if (ok != 1)
        ERR_raise(ERR_LIB_DH, ERR_R_BN_LIB);

    if (pub_key != dh->pub_key)
        BN_free(pub_key);
    if (priv_key != dh->priv_key)
        BN_free(priv_key);
    BN_CTX_free(ctx);

    return ok;
}