#include <stdio.h>
#include <stdarg.h>
#include "ftplog.h"
#include <errno.h>

void LOG(ftplog_type type, const char* format, ...)
{
    va_list args;
    va_start(args, format);
    FILE *logfile;

    switch (type)
    {
    case CLIENT_LOG:
        logfile = fopen(FTP_CLIENT_LOG_FILE, "a");
        break;
    
    case SERVER_LOG:
        logfile = fopen(FTP_SERVER_LOG_FILE, "a");
    
    default:
        break;
    }

    if (logfile == NULL) 
    {
        fprintf(stderr, "Error opening log file: %s\n", strerror(errno));
        return;
    }

    int result = vfprintf(logfile, format, args);
    if (result < 0) 
    {
        fprintf(stderr, "Error writing to log file: %s\n", strerror(errno));
    }

    fclose(logfile);
    va_end(args);
}


