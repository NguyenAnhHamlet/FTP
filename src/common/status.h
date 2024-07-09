#ifndef __STATUS__
#define __STATUS__


#include <stdio.h>
#include <string.h>


typedef enum 
{
    SEND_START = 125,
    SEND_SUCC = 226,
    CON_CLOSE =     426, 
    ABORT =         451,
    FILE_UN = 550 
} status_ftp;


#endif