#include "control.h"
#include "common/common.h"
#include <stdbool.h>
#include <stdlib.h>
#include "secure/secure.h"
#include "common/timer.h"
#include <time.h>
#include "common/channel.h"
#include "common/socket_ftp.h"
#include "common/packet.h"
#include "data.h"
#include "control.h"
#include "cmd.h"
#include <ctype.h>
#include <string.h>
#include <sys/types.h>
#include "common/file.h"

// Pattern in config file
typedef enum 
{
    PubkeyAcceptedKeyTypes,
    KexkeyAcceptedKeyTypes,
    ChannelPort,
    // DataPort,
    IdleTimeOut
} client_opcode;

typedef struct 
{
    unsigned int pkeyaccept;
    unsigned int kexkey_accept;
    // unsigned int dataport;
    unsigned int controlport;
    unsigned int addrfamily;
    unsigned int idle_timeout; 
} client_config_st;

