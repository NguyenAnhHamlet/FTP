#include <openssl/err.h>

void openssl_get_error()
{
    ERR_print_errors_fp(stderr);
}
