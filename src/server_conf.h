#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h> 
#include "secure/secure.h"
#include "log/ftplog.h"
#include "common/timer.h"
#include <signal.h>
#include <fcntl.h>
#include "common/socket_ftp.h"
#include "common/pam.h"
#include "common/packet.h"
#include <pwd.h>
#include "cmd.h"
#include "common/file.h"
#include "data.h"
#include "control.h"

typedef struct 
{
    unsigned int pkeyaccept;
    unsigned int kexkey_accept;
    unsigned int rlogin;
    unsigned int maxauth;
    unsigned int passauth;
    // unsigned int dataport;
    unsigned int controlport;
    unsigned int addrfamily;
    unsigned int idle_tmout;
} server_config_st;

// Pattern in config file
typedef enum 
{
    PubkeyAcceptedKeyTypes,
    KexkeyAcceptedKeyTypes,
    IdleTimeOut,
    MaxAuthTries,
    PermitRootLogin,
    ChannelPort,
    DataPort
} server_opcode;
