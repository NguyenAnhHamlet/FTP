#ifndef __SERVER__
#define __SERVER__

#include "common.h"
#include "receive.h"
#include "send.h"

// Data command
#define GET "get"
#define PUT "put"
#define RECV "recv"
#define SEND "send"

// Server side commands
#define ACCOUNT "account"
#define APPEND "append"
#define CASE "case"
#define CD "cd"
#define CDUP "cdup"
#define CHMOD "chmod"
#define DELETE "delete"
#define DIR "dir"
#define IPANY "ipany"
#define IPV4 "ipv4"
#define IPV6 "ipv6"
#define LCD "lcd"
#define LS "ls"
#define IDLE "idle"
#define MDELETE "mdelete"
#define MDIR "mdir"
#define MGET "mget"
#define MKDIR "mkdir"
#define MLS "mls"
#define MODE "mode"
#define MODTIME "modtime"
#define MPUT "mput"
#define NEWER "newer"
#define NLIST "nlist"
#define NMAP "nmap"
#define NTRANS "ntrans"
#define OPEN "open"
#define PASSIVE "passive"
#define PROMPT "prompt"
#define PROXY "proxy"
#define PWD "pwd"
#define QC "qc"
#define QUIT_SERVER "quit_server"
#define QUOTE "quote"
#define REGET "reget"
#define RENAME "rename"
#define RESET "reset"
#define RESTART "restart"
#define RHELP "rhelp"
#define RMDIR "rmdir"
#define RSTATUS "rstatus"
#define RUNIQUE "runique"
#define SENDPORT "sendport"
#define SITE "site"
#define SIZE "size"
#define STATUS "status"
#define STRUCT "struct"
#define SUNIQUE "sunique"
#define SYSTEM "system"
#define TENEX "tenex"
#define TICK "tick"
#define TRACE "trace"
#define TYPE "type"
#define USER "user"

// Handle the request :
// Open data PORT to send, recv file
// Send back the data to control PORT
int handleRequestServer(int sockfd, char req[]);

// Data command functions
int get();
int put();
int recvFile();
int sendFile();

// Server side functions
int account();
int append();
int case_();
int cd();
int cdup();
int chmod();
int delete_();
int dir();
int ipany();
int ipv4();
int ipv6();
int lcd();
int ls();
int idle();
int mdelete();
int mdir();
int mget();
int mkdir();
int mls();
int mode();
int modtime();
int mput();
int newer();
int nlist();
int nmap();
int ntrans();
int open();
int passive();
int prompt();
int proxy();
int pwd();
int qc();
int quit_server();
int quote();
int reget();
int rename_();
int reset();
int restart();
int rhelp();
int rmdir();
int rstatus();
int runique();
int sendport();
int site();
int size();
int status();
int struct_();
int sunique();
int system_();
int tenex();
int tick();
int trace();
int type();
int user();

#endif