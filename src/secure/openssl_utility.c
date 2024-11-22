#include <openssl/err.h>

void openssl_get_error()
{
    unsigned long err_code = ERR_get_error();
    if (err_code) 
    {
        char err_buf[120];
        ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
        fprintf(stderr, "Error: %s\n", err_buf);
    }
}
