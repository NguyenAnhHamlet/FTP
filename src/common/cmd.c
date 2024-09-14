#include "cmd.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "algo/algo.h"
#include "log/ftplog.h"

unsigned int get_cmd(char* cmd)
{
    FILE *fp;
    char* cmd_pipe;
    char* res;
    int len;
    int res_int;

    cmd_pipe = "awk -F ' *= *' /";
    strcat(cmd_pipe, cmd);
    strcat(cmd_pipe, "/ {print $2} ");
    strcat(cmd_pipe, cmd_file); 

    fp = popen(cmd_pipe, "r");

    if (fp == NULL) 
    {
        LOG(CLIENT_LOG, "Failed to run command\n" );
        exit(1);
    }

    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    rewind(fp);

    res = (char *)malloc(sizeof(char) * len);
    if(fread(res, 1, len, fp ) < 1)
    {
        LOG(CLIENT_LOG, "Failed to read buffer\n");
        return 0;
    }

    res_int = str_to_int(res, len);

    fclose(fp);
    free(res);

    return res_int;
}