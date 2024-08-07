#include <stdio.h>
#include <stdarg.h>
#include "ftplog.h"

void LOG(const char* format, ...)
{
    
    va_list args;
    va_start(args, format);

    FILE *logfile = fopen(FTP_LOG_FILE, "a");

    vfprintf(logfile, format, args);
    va_end(args);
}