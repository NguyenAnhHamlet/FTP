#include <stdio.h>
#include <stdarg.h>
#include "ftplog.h"

void LOG(const char* format, ...)
{
    va_list args;
    va_start(args, format);

    vfprintf(FTP_LOG_FILE, format, args);
    va_end(args);
}