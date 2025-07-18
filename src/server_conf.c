#include "server_conf.h"

server_config_st server_config;

static struct {
	const char *name;
	server_opcode opcode;
} keywords[] = {
    {"PubkeyAcceptedKeyTypes", PubkeyAcceptedKeyTypes},
    {"rsa", RSAK},
    {"ed25519", ED25519K},
    {"KexkeyAcceptedKeyTypes", KexkeyAcceptedKeyTypes},
    {"ecdh", ECK},
    {"dh", DHK},
    {"IdleTimeOut", IdleTimeOut},
    {"MaxAuthTries", MaxAuthTries},
    {"PermitRootLogin", PermitRootLogin},
    {"ChannelPort", ChannelPort},
    // {"DataPort", DataPort},
    {NULL, 0}
};

int parse_token(const char *cp, const char *filename,
	    int linenum)
{
	unsigned int i;

	for (i = 0; keywords[i].name; i++)
		if (strncmp(cp, keywords[i].name, strlen(cp)) == 0)
			return keywords[i].opcode;

	fprintf(stderr, "%s: line %d: Bad configuration option: %s\n",
		filename, linenum, cp);
	return -1;
}

int read_config(char* conf)
{
    FILE* fp = NULL;    
    read_file(conf, &fp);
    char* cp = NULL; 
    int opcode;
    
    char line[1024];
    int linenum = 0;
    while(fgets(line, 1024, fp))
    {
        linenum++;  
        cp = line + strspn(line, WHITESPACE);
        if (!*cp || *cp == '#')
			continue;
        cp = strtok(cp, WHITESPACE);
        opcode = parse_token(cp, conf, linenum);

        switch(opcode)
        {
            case PubkeyAcceptedKeyTypes:
            {
                int ret = 0;
                while(cp = strtok(NULL, WHITESPACE))
                {
                    opcode = parse_token(cp, conf, linenum);
                    ret |= opcode;
                }
                server_config.pkeyaccept = ret;

                break;
            }
            case KexkeyAcceptedKeyTypes:
            {
                int ret = 0;
                while(cp = strtok(NULL, WHITESPACE))
                {
                    opcode = parse_token(cp, conf, linenum);
                    ret |= opcode;
                }
                printf("ret : %d\n", ret);
                server_config.kexkey_accept = ret;
                break;
            }
            case IdleTimeOut:
            {
                cp = strtok(NULL, WHITESPACE);
                printf("%s\n", cp);
                server_config.idle_tmout = str_to_int(cp, strlen(cp));
                printf("%d\n", server_config.idle_tmout);
                break;
            }
            case MaxAuthTries:
            {
                cp = strtok(NULL, WHITESPACE);
                printf("%s\n", cp);
                server_config.maxauth = str_to_int(cp, strlen(cp));
                printf("%d\n", server_config.maxauth);
                break;
            }
            case PermitRootLogin:
            {
                cp = strtok(NULL, WHITESPACE);
                printf("%s\n", cp);
                if(strncmp(cp, "no", strlen(cp)))
                    server_config.rlogin = 0;
                else 
                    server_config.rlogin = 1;
                printf("%d\n", server_config.rlogin);
                break;
            }
            case ChannelPort:
            {
                cp = strtok(NULL, WHITESPACE);
                printf("%s\n", cp);
                server_config.controlport = str_to_int(cp, strlen(cp));
                printf("%d\n", server_config.controlport);
                break;
            }
            // case DataPort:
            // {
            //     cp = strtok(NULL, WHITESPACE);
            //     printf("%s\n", cp);
            //     server_config.controlport = str_to_int(cp, strlen(cp));
            //     printf("%d\n", server_config.controlport);
            //     break;
            // }
        }
    }

    return 1;
}