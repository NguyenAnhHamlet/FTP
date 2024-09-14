#include <openssl/bn.h>

int main() {
    BIGNUM *bn = BN_new();
    BN_set_word(bn, 123456789);

    int num_bytes = BN_num_bytes(bn);
    int num_bits = BN_num_bits(bn);

    printf("Number of bytes: %d\n", num_bytes);
    printf("Number of bits: %d\n", num_bits);

    BN_free(bn);
    return 0;
}
