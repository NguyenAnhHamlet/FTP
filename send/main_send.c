#include "send.h"
#include <stdio.h>
#include <sys/stat.h>
#include "common.h"

int main(int argc, char *argv[])
{
    // need at least 3 argv : file path, mode and IP  
    if(argc < 3) 
    {
        printf("Need file and destination's IP address\n");
        return -1;
    }

    // mode need to be -f or -m
    if( strcmp(argv[1], "-f") |  strcmp(argv[1], "-m"))
    {
        printf("Please specify correctly whether send file or msg\n");
        return -1;
    }

    // if file path exist
    if(argv[1] == '-f')
    {
        if(!access(argv[1], F_OK))
        {
            printf("File does not exist\n");
            return -1;
        }

        // if file is not readable
        if(!access(argv[1], R_OK))
        {
            printf("File is not redable, change permission\n");
            chmod(argv[1], R_O_ALL);
        }
    }

    // IP address is valid
    if(!isIpAddr(argv[2]))
    {
        printf("IP address is not valid\n");
        return -1;
    }

    // all condition sastified, start creating connection and send
    // file over

    return 0;
}