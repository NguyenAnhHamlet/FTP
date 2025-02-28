#ifndef __CMD__
#define __CMD__

#include "common/channel.h"

#define GET         500
#define PUT         501
#define APPEND      502
#define LCD         503
#define CD          504
#define CHMOD       505
#define DELETE      506
#define _DIR        507
#define LLS         508
#define LS          509
#define IDLE        510
#define MDELETE     511
#define MDIR        512
#define MGET        513
#define MKDIR       514
#define MLS         515
#define MODTIME     516
#define MPUT        517
#define NEWER       518
#define NLIST       519
#define PROMPT      520
#define PWD         521
#define REGET       522
#define RENAME      523
#define RESTART     524
#define RMDIR       525
#define SIZE        526
#define STATUS      527
#define SYSTEM      528
#define IPV4_OP     529
#define IPV6_OP     530
#define PASSMODE    531
#define BGET        532
#define BPUT        533
#define BMGET       534 
#define BMPUT       535
#define MMKDIR      536 
#define LPWD        537

typedef int (* command_func_ptr) (channel_context*); 
typedef struct 
{
    char* command_str;
    unsigned int command_code;
    command_func_ptr func ;
    char* helper;
} command;

int islocal_func(unsigned int code);

#endif