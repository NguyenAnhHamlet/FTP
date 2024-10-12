#include "cmd.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "algo/algo.h"
#include "log/ftplog.h"

// Get the command and the contents of buffer ppointed by cmd and contents
// Return result will be the ftp's command code
// Remember don't free or destroy the buffer, or else there will be coredump   
unsigned int get_cmd_contents(unsigned char* buffer, unsigned char** cmd, 
                              unsigned char** contents)
{
    // get the command 
    *cmd = buffer;
    *contents = strchr(buffer, ' ');
    if( *contents == NULL) return 0;
    **contents = '\0';
    *contents++;

    if (strcmp(*cmd, GET_STR) == 0)
        return GET;

    if (strcmp(*cmd, PUT_STR) == 0)
        return PUT;

    if (strcmp(*cmd, RECV_STR) == 0)
        return RECV;

    if (strcmp(*cmd, SEND_STR) == 0)
        return SEND;

    if (strcmp(*cmd, APPEND_STR) == 0)
        return APPEND;

    if (strcmp(*cmd, CASE_STR) == 0)
        return CASE;

    if (strcmp(*cmd, CD_STR) == 0)
        return CD;

    if (strcmp(*cmd, CHMOD_STR) == 0)
        return CHMOD;

    if (strcmp(*cmd, DELETE_STR) == 0)
        return DELETE;

    if (strcmp(*cmd, DIR_STR) == 0)
        return _DIR;

    if (strcmp(*cmd, LCD_STR) == 0)
        return LCD;

    if (strcmp(*cmd, LS_STR) == 0)
        return LS;

    if (strcmp(*cmd, IDLE_STR) == 0)
        return IDLE;

    if (strcmp(*cmd, MDELETE_STR) == 0)
        return MDELETE;

    if (strcmp(*cmd, MDIR_STR) == 0)
        return MDIR;

    if (strcmp(*cmd, MGET_STR) == 0)
        return MGET;

    if (strcmp(*cmd, MKDIR_STR) == 0)
        return MKDIR;

    if (strcmp(*cmd, MLS_STR) == 0)
        return MLS;

    if (strcmp(*cmd, MODTIME_STR) == 0)
        return MODTIME;

    if (strcmp(*cmd, MPUT_STR) == 0)
        return MPUT;

    if (strcmp(*cmd, NEWER_STR) == 0)
        return NEWER;

    if (strcmp(*cmd, NLIST_STR) == 0)
        return NLIST;

    if (strcmp(*cmd, PROMPT_STR) == 0)
        return PROMPT;

    if (strcmp(*cmd, PWD_STR) == 0)
        return PWD;

    if (strcmp(*cmd, QC_STR) == 0)
        return QC;

    if (strcmp(*cmd, REGET_STR) == 0)
        return REGET;

    if (strcmp(*cmd, RENAME_STR) == 0)
        return RENAME;

    if (strcmp(*cmd, RESET_STR) == 0)
        return RESET;

    if (strcmp(*cmd, RESTART_STR) == 0)
        return RESTART;

    if (strcmp(*cmd, RHELP_STR) == 0)
        return RHELP;

    if (strcmp(*cmd, RMDIR_STR) == 0)
        return RMDIR;

    if (strcmp(*cmd, RSTATUS_STR) == 0)
        return RSTATUS;

    if (strcmp(*cmd, SIZE_STR) == 0)
        return SIZE;

    if (strcmp(*cmd, STATUS_STR) == 0)
        return STATUS;

    if (strcmp(*cmd, SYSTEM_STR) == 0)
        return SYSTEM;

    if (strcmp(*cmd, TICK_STR) == 0)
        return TICK;

    if (strcmp(*cmd, IPV4_OP_STR) == 0)
        return IPV4_OP;

    if (strcmp(*cmd, IPV6_OP_STR) == 0)
        return IPV6_OP;

    if (strcmp(*cmd, PASSMODE_STR) == 0)
        return PASSMODE;

    if (strcmp(*cmd, INT_OFF_STR) == 0)
        return INT_OFF;

    if (strcmp(*cmd, AULOG_DIS_STR) == 0)
        return AULOG_DIS;

    if (strcmp(*cmd, GLOB_DIS_STR) == 0)
        return GLOB_DIS;

    if (strcmp(*cmd, VERBOSE_ENB_STR) == 0)
        return VERBOSE_ENB;

    if (strcmp(*cmd, DEBUG_ENB_STR) == 0)
        return DEBUG_ENB;
    
    return 0;
    
}