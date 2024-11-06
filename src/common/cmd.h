#ifndef __CMD__
#define __CMD__

#define GET         500
#define PUT         501
#define RECV        502
#define SEND        503
#define APPEND      504
#define CASE        505
#define CD          506
#define CHMOD       507
#define DELETE      508
#define _DIR        509
#define LCD         510
#define LS          511
#define IDLE        512
#define MDELETE     513
#define MDIR        514
#define MGET        515
#define MKDIR       516
#define MLS         517
#define MODTIME     518
#define MPUT        519
#define NEWER       520
#define NLIST       521
#define PROMPT      522
#define PWD         523
#define QC          524
#define REGET       525
#define RENAME      526
#define RESET       527
#define RESTART     528
#define RHELP       529
#define RMDIR       530
#define RSTATUS     531
#define SIZE        532
#define STATUS      533
#define SYSTEM      534
#define TICK        535
#define IPV4_OP     536
#define IPV6_OP     537
#define PASSMODE    538
#define INT_OFF     539
#define AULOG_DIS   540
#define GLOB_DIS    541
#define VERBOSE_ENB 542
#define DEBUG_ENB   543
#define CLEAR       544

// Get the command and the contents of buffer pointed by cmd and contents
// Return result will be the ftp's command code
// Remember don't free or destroy the buffer, or else there will be coredump 
unsigned int get_cmd_contents(unsigned char* buffer, unsigned char** cmd, 
                              unsigned char** contents);

#endif