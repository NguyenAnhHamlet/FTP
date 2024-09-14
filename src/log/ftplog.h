#ifndef __FTPLOG__
#define __FTPLOG__

#include<string.h>

#define FTP_CLIENT_LOG_FILE "/var/log/ftp.log"
#define FTP_SERVER_LOG_FILE "/var/log/ftpserver.log"

typedef enum 
{
    CLIENT_LOG,
    SERVER_LOG
}
ftplog_type;

void LOG(ftplog_type type, const char* format, ...);


#endif
