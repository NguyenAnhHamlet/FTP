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

#define GET_STR         "get"
#define PUT_STR         "put"  
#define RECV_STR        "recv"
#define SEND_STR        "send"
#define APPEND_STR      "append"
#define CASE_STR        "case"
#define CD_STR          "cd"
#define CHMOD_STR       "chmod"
#define DELETE_STR      "delete"
#define DIR_STR         "dir"
#define LCD_STR         "lcd"
#define LS_STR          "ls"
#define IDLE_STR        "idle"
#define MDELETE_STR     "mdelete"
#define MDIR_STR        "mdir"
#define MGET_STR        "mget"
#define MKDIR_STR       "mkdir"
#define MLS_STR         "mls"
#define MODTIME_STR     "modtime"
#define MPUT_STR        "mput"
#define NEWER_STR       "newer"
#define NLIST_STR       "nlist"
#define PROMPT_STR      "prompt"
#define PWD_STR         "pwd"
#define QC_STR          "qc"
#define REGET_STR       "reget"
#define RENAME_STR      "rename"
#define RESET_STR       "reset"
#define RESTART_STR     "restart"
#define RHELP_STR       "rhelp"
#define RMDIR_STR       "rmdir"
#define RSTATUS_STR     "rstatus"
#define SIZE_STR        "size"
#define STATUS_STR      "status"
#define SYSTEM_STR      "system"
#define TICK_STR        "tick"
#define IPV4_OP_STR     "ipv4_op"
#define IPV6_OP_STR     "ipv6_op"
#define PASSMODE_STR    "passmode"
#define INT_OFF_STR     "int_off"
#define AULOG_DIS_STR   "aulog_dis"
#define GLOB_DIS_STR    "glob_dis"
#define VERBOSE_ENB_STR "verbose_enb"
#define DEBUG_ENB_STR   "debug_enb"

unsigned int get_cmd_contents(unsigned char* buffer, unsigned char** cmd, 
                              unsigned char** contents);

#endif