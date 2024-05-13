#ifndef __FTP__ 
#define __FTP__

#include <stdio.h>
#include "common.h"

// !	Temporarily escape to the local shell.
// $	Execute a macro.
// ?	Display help text.
// account	Supply a password for the remote system.
// append	Append a local file to a file on the remote system.
// ascii	Set the file transfer type to network ASCII (default type).
// bell	Enable a sound alert after each transfer is complete.
// binary	Set the file transfer type to binary image transfer.
// bye	Exit the FTP interface.
// case	Toggle upper/lower case sensitivity when ID mapping during the mget command.
// cd	Change the current working directory on the remote system.
// cdup	Change to the parent of the current working directory on the remote system.
// chmod	Change file permissions on the remote system.
// close	Exit the FTP interface.
// cr	Toggle carriage return stripping on ASCII file transfers.
// debug	Toggle debugging mode.
// delete	Delete a file from the remote system.
// dir	List the contents of a directory on the remote system.
// disconnect	Terminate the FTP session.
// exit	Terminate the FTP session and exit the FTP interface.
// form	Set the file transfer format.
// get	Transfer a file from the remote system to the local machine.
// glob	Toggle meta character expansion of local file names.
// hash	Toggle displaying the hash sign ("#") for each transferred data block.
// help	Display help text.
// idle	Set an inactivity timer for the remote system.
// image	Set the file transfer type to binary image transfer.
// ipany	Allow any type of IP address.
// ipv4	Only allow IPv4 addresses.
// ipv6	Only allow IPv6 addresses.
// lcd	Change the current working directory on the local machine.
// ls	List the contents of a directory on the remote system.
// macdef	Define a macro.
// mdelete	Delete multiple files on the remote system.
// mdir	List the contents of multiple directories on the remote system.
// mget	Transfer multiple files from the remote system to the local machine.
// mkdir	Create a directory on the remote system.
// mls	List the contents of multiple directories on the remote system.
// mode	Set the file transfer mode.
// modtime	Show the last time a file on the remote system was modified.
// mput	Transfer multiple files from the local machine to the remote system.
// newer	Transfer a file from the remote system to the local machine only if the modification time of the remote file is more recent than that of the local file (if a local version of the file doesn't exist, the remote file is automatically considered newer).
// nlist	List the contents of a directory on the remote system.
// nmap	Set templates for default file name mapping.
// ntrans	Set translation table for default file name mapping.
// open	Establish a connection with an FTP server.
// passive	Enable passive transfer mode.
// prompt	Force interactive prompts when transferring multiple files.
// proxy	Execute command on an alternate (proxy) connection.
// put	Transfer a file from the local machine to the remote system.
// pwd	Display the current working directory on the remote system.
// qc	Toggle displaying a control character ("?") in the output of ASCII type commands.
// quit	Terminate the FTP session and exit the FTP interface.
// quote	Specify a command as an argument and send it to the FTP server.
// recv	Transfer a file from the remote system to the local machine.
// reget	Transfer a file from the remote system to the local machine if the local file is smaller than the remote file. The transfer starts at the end of the local file. If there is no local version of the file, the command doesn't execute.
// rename	Rename a file on the remote system.
// reset	Clear queued command replies.
// restart	Restart a file transfer command at a set marker.
// rhelp	Display help text for the remote system.
// rmdir	Remove a directory on the remote system.
// rstatus	Show the status of the remote system.
// runique	Toggle storing files on the local machine with unique filenames.
// send	Transfer a file from the local machine to the remote system.
// sendport	Toggle the use of PORT commands.
// site	Specify a command as an argument and send it to the FTP server as a SITE command.
// size	Display the size of a file on the remote system.
// status	Show the status of the FTP interface.
// struct	Set the file transfer structure.
// sunique	Toggle storing files on the remote system with unique filenames.
// system	Show the operating system on the remote system.
// tenex	Set the file transfer type to allow connecting to TENEX machines.
// tick	Toggle printing byte counter during transfers.
// trace	Toggle packet tracing.
// type	Set a file transfer type.
// umask	Set a default permissions mask for the local machine.
// user	Provide username and password for the remote FTP server.
// verbose	Toggle verbose output.


// Options
#define IPV4_OP "-4"
#define IPV6_OP "-6"
#define PASSMODE "-p"
#define INT_OFF "-i"
#define AULOG_DIS "-n"
#define GLOB_DIS "-g"
#define VERBOSE_ENB "-v"
#define DEBUG_ENB "-d"

// Client side commands
#define QUIT "quit"
#define HELP "help"
#define ASCII "ascii"
#define BELL "bell"
#define BINARY "binary"
#define BYE "bye"
#define CLOSE "close"
#define CR "cr"
#define DEBUG "debug"
#define DISCONNECT "disconnect"
#define EXIT "exit"
#define FORM "form"
#define GLOB "glob"
#define HASH "hash"
#define HELP_CLIENT "help_client"
#define IMAGE "image"
#define MACDEF "macdef"
#define VERBOSE "verbose"
#define UMASK "umask"

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

int sendClientRequest(char req[], Asym_Infos* as_infos, Timer* timer);

int handleRequest(char req[], Asym_Infos* as_infos, Timer* timer);

int recvServerReply(char rep[], Asym_Infos* as_infos, Timer* timer);

int handleReply(char rep[], Asym_Infos* as_infos, Timer* timer);

int handleOption(char option[]);

// Options functions
void ipv4_op(_socketFTP* socketFTP);
void ipv6_op(_socketFTP* socketFTP);
void passmode(_socketFTP* socketFTP);
void int_off(_socketFTP* socketFTP);
void aulog_dis(_socketFTP* socketFTP);
void glob_dis(_socketFTP* socketFTP);
void verbose_enb(_socketFTP* socketFTP);
void debug_enb(_socketFTP* socketFTP);

// Client side functions
int quit();
int help();
int ascii();
int bell();
int binary();
int bye();
int close();
int cr();
int debug();
int disconnect();
int exit_cmd();
int form();
int glob();
int hash();
int help_client();
int image();
int macdef();
int verbose();
int umask();

// Data command functions
int get();
int put();
int recv();
int send();

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