#include "cmd.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "algo/algo.h"
#include "log/ftplog.h"
  
unsigned int get_cmd_contents(unsigned char* buffer, unsigned char** cmd, 
                              unsigned char** contents)
{
    // get the command 
    *cmd = buffer;
    *contents = strchr(buffer, ' ');
    if(*contents)
    {
        **contents = '\0';
        (*contents)++;
    }
    
    return 1;
    
}