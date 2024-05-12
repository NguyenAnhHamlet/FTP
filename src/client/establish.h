#ifndef __ESTABLISH__ 
#define __ESTABLISH__

#include <stdio.h>
#include <string.h>

// -4	Use only IPv4.
// -6	Use only IPv6.
// -e	Disables command editing and history support.
// -p	Uses passive mode for data transfers, allowing you to use FTP despite a firewall that might prevent it.
// -i	Turns off interactive prompting during multiple file transfers.
// -n	Disables auto-login attempts on initial connection.
// -g	Disables file name globbing.
// -v	Enables verbose output.
// -d	Enables debugging.

#define IPV4        "-4"
#define IPV6        "-6"
#define EDIT_DIS    "-e"
#define P_MODE      "-p"
#define I_OFF       "-i"
#define ALOG_DIS    "-n"
#define GLOB_DIS    "-g"
#define VER_OUT     "-v"
#define DEBUG_ENB   "-d"


#endif