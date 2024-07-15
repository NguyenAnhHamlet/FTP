#ifndef __FTPLOG__
#define __FTPLOG__

#include<string.h>

#define FTP_LOG_FILE "/var/log/ftp.log"

void LOG(const char* format, ...);


#endif
