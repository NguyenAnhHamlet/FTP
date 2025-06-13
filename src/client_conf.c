#include "client_conf.h"

static struct {
	const char *name;
	client_opcode opcode;
} keywords[] = {
    {"PubkeyAcceptedKeyTypes", PubkeyAcceptedKeyTypes},
    {"rsa", RSAK},
    {"ed25519", ED25519K},
    {"KexkeyAcceptedKeyTypes", KexkeyAcceptedKeyTypes},
    {"ecdh", ECK},
    {"dh", DHK},
    {"ChannelPort", ChannelPort},
    {"IdleTimeOut", IdleTimeOut},
    // {"DataPort", DataPort},
    {NULL, 0}
};

client_config_st client_config;

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
                // printf("ret : %d\n", ret);
                client_config.pkeyaccept = ret;
                break;
            }
            case KexkeyAcceptedKeyTypes:
            {
                int ret = 0;
                // cp = strtok(NULL, WHITESPACE);
                while(cp = strtok(NULL, WHITESPACE))
                {
                    opcode = parse_token(cp, conf, linenum);
                    ret |= opcode;
                }
                // printf("ret : %d\n", ret);
                client_config.kexkey_accept = ret;
                break;
            }
            case ChannelPort:
            {
                cp = strtok(NULL, WHITESPACE);
                // printf("%s\n", cp);
                client_config.controlport = str_to_int(cp, strlen(cp));
                // printf("%d\n", client_config.controlport);
                break;
            }
            case IdleTimeOut:
            {
                cp = strtok(NULL, WHITESPACE);
                printf("%s\n", cp);
                client_config.idle_timeout= str_to_int(cp, strlen(cp));
                printf("%d\n", client_config.idle_timeout);
                break;                
            }
            // case DataPort:
            // {
            //     cp = strtok(NULL, WHITESPACE);
            //     printf("%s\n", cp);
            //     client_config.controlport = str_to_int(cp, strlen(cp));
            //     printf("%d\n", client_config.controlport);
            //     break;
            // }
        }
    }

    return 1;
}
