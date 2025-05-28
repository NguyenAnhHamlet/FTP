#include "control.h"
#include "common/common.h"
#include <stdbool.h>
#include <stdlib.h>
#include "secure/secure.h"
#include "common/timer.h"
#include <time.h>
#include <signal.h>
#include "common/channel.h"
#include "common/socket_ftp.h"
#include "common/packet.h"
#include "data.h"
#include "control.h"
#include "cmd.h"
#include "log/ftplog.h"
#include "algo/algo.h"
#include <readline/readline.h>
#include <readline/history.h>
#include <ctype.h>
#include <string.h>
#include <sys/types.h>
#include "common/file.h"

#define IPADDR_SIZE  32
#define OPTION_SIZE  8

extern command commands[];
channel_context channel_ctx;
bool ftp_running;
control_channel c_channel;
data_channel d_channel;
socket_ftp*  c_socket;
socket_ftp* d_socket;
char ipaddr[IPADDR_SIZE];
char option[OPTION_SIZE];
unsigned int iptype;

// Pattern in config file
typedef enum 
{
    PubkeyAcceptedKeyTypes,
    KexkeyAcceptedKeyTypes,
    ChannelPort,
    // DataPort,
    IdleTimeOut
} client_opcode;

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

static struct 
{
    unsigned int pkeyaccept;
    unsigned int kexkey_accept;
    // unsigned int dataport;
    unsigned int controlport;
    unsigned int addrfamily;
    unsigned int idle_timeout; 
} client_config;

// Get the command and the contents of buffer pointed by cmd and contents
// Return result will be the ftp's command code
// Remember don't free or destroy the buffer, or else there will be coredump 
unsigned int get_cmd_contents(unsigned char* buffer, unsigned char** cmd, 
                              unsigned char** contents)
{
    // get the command 
    *cmd = buffer;
    *contents = strchr(buffer, ' ');
    if(*contents)
    {
        **contents = '\0';
        (*contents)++;
    }
    
    return 1;
}

/* Strip whitespace from the start and end of STRING.  Return a pointer
   into STRING. */
char *stripwhite (char *string)
{
  register char *s, *t;

  for (s = string; whitespace (*s); s++)
    ;
    
  if (*s == 0)
    return (s);

  t = s + strlen (s) - 1;
  while (t > s && whitespace (*t))
    t--;
  *++t = '\0';

  return s;
}

int run_command(channel_context* channel_ctx, char* command_str)
{
    for(int i =0; commands[i].command_str != NULL; i++)
    {
        LOG(CLIENT_LOG, "str : %s\n", commands[i].command_str);
        if(!strcmp(commands[i].command_str, command_str))
        {
            printf("%s",commands[i].helper);
            printf("\n");
            printf("%s\n", commands[i].command_str);
            if(!islocal_func(commands[i].command_code))
            {
                control_channel_append_ftp_type(commands[i].command_code, channel_ctx->c_channel);
                control_channel_send(channel_ctx->c_channel);
            }

            return commands[i].func(channel_ctx);
        }
    }

    return 0;
}

void client_terminate_connection(control_channel* c_channel);

void handle_init_command(int argc, char* argvs[])
{
    strncpy(ipaddr, argvs[1], IPADDR_SIZE);
    argc > 2 ? strncpy(option, argvs[2], OPTION_SIZE) : memset(option, '\0', OPTION_SIZE); 
    printf("%s\n", ipaddr);
    printf("%s\n", option);
}

int quit() 
{
    ftp_running = 0;
    client_terminate_connection(&c_channel);
    // exit the program to prevent issue
    exit(EXIT_SUCCESS);
    return 0;
}

void time_out_alarm(int sig)
{
    enable_echo();
    fatal("Time out");
}

void signal_handler(int sig)
{
    LOG(CLIENT_LOG, "Received signal %d; terminating.", sig);
    quit();
}

void client_terminate_connection(control_channel* c_channel)
{
    control_channel_append_ftp_type(TERMINATE, c_channel);
    control_channel_send(c_channel);
}

void ipv4_op_set(socket_ftp* s_ftp)
{
    s_ftp->endpoint_addr->sin_family = AF_INET;
}

void ipv6_op_set(socket_ftp* s_ftp)
{
    s_ftp->endpoint_addr->sin_family = AF_INET6;
}

int handle_option(socket_ftp* s_ftp, unsigned int op)
{
    switch (op)
    {
    case IPV4_OP:
        ipv4_op_set(s_ftp);
        break;
    case IPV6_OP:
        ipv6_op_set(s_ftp);
    default:
        break;
    }
}

void callBackTimer(timer* timer)
{
    fatal("Time out\n");
}

int password_authen_client(control_channel* c_channel, cipher_context *ctx)
{
    if(!c_channel) return -1;

    char* name = NULL;
    char* pass = NULL;
    char *pass_enc = NULL;
    char *name_enc = NULL;

    int name_enc_len, pass_enc_len;

restart: 
    // memset(name, '\0', BUF_LEN);
    // memset(pass, '\0', BUF_LEN);

    // TODO: 
    // change to readline which allow user to update text
    name = readline("Name: ");
    if(!name) 
    {
        fprintf(stdout, "Please enter user name");
        goto restart;
    }

    disable_echo();
    pass = readline("Pass: ");
    if(!pass)
    {
        free(name);
        fprintf(stdout, "Please enter user name and pass again");
        enable_echo();
        goto restart;
    }

    enable_echo();

    LOG(SERVER, "name : %s\n", name);
    LOG(SERVER, "pass : %s\n", pass);

    // init 
    name_enc = (char*) malloc(strlen(name) +  EVP_MAX_BLOCK_LENGTH);
    pass_enc = (char*) malloc(strlen(pass) +  EVP_MAX_BLOCK_LENGTH);

    
    // encrypt the name and the password 
    aes_cypher_encrypt(ctx, name, strlen(name), name_enc, &name_enc_len);
    aes_cypher_encrypt(ctx, pass, strlen(pass), pass_enc, &pass_enc_len);    
    
    free(name);
    free(pass);
    
    control_channel_append_ftp_type(FTP_PASS_AUTHEN, c_channel);
    control_channel_append_str(name_enc, c_channel, name_enc_len);
    control_channel_send_wait(c_channel);

    control_channel_append_ftp_type(FTP_PASS_AUTHEN, c_channel);
    control_channel_append_str(pass_enc, c_channel, pass_enc_len);
    control_channel_send_wait(c_channel);

    if(control_channel_read_expect(c_channel, FTP_ACK))
    {
        fprintf(stdout, "Pass authenticate succeed\n");
        free(name_enc);
        free(pass_enc); 
        return 1;
    }

    if(control_channel_get_ftp_type_in(c_channel) == FTP_NACK)
    {
        free(name_enc);
        free(pass_enc);
        fatal("Pass authenticate failed\n");
    }

    if(control_channel_get_ftp_type_in(c_channel) == FTP_ROOT_DENY)
    {
        free(name_enc);
        free(pass_enc); 
        fatal("User has root privileges denied\n");
    }

    fprintf( stdout, "Pass authentication failed, retry: \n");
    
goto restart;

}

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

int main(int argc, char* argvs[])
{
    char conf[] = "/etc/ftp/sftp_config"; 
    char* buffer;
    unsigned int request_int; 
    unsigned char* cmd;
    unsigned char* arg;
    cipher_context* ctx;
    char* line = NULL;

    read_config(conf);

    // init
    ctx = (cipher_context* ) malloc(sizeof(cipher_context)); 
    aes_cipher_init(ctx);
    channel_ctx.control_port = client_config.controlport;
    // channel_ctx.data_port = client_config.dataport;

    // signal and handle
    signal(SIGINT, signal_handler);
    signal(SIGQUIT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, signal_handler);

    handle_init_command(argc, argvs);

    // Create a FTP socket
    c_socket = create_ftp_socket(ipaddr, AF_INET, CLIENT, 
                                 channel_ctx.control_port, 
                                 CONTROL, cre_socket());
    
    control_channel_init_socket_ftp(&c_channel, c_socket, 
                                    c_socket, CLIENT, NULL);

    control_channel_set_time_out(&c_channel, DEFAULT_CHANNEL_TMOUT);

    // set alarm for 30 
    signal(SIGALRM, time_out_alarm);
	alarm(30);

    if(!(client_config.pkeyaccept = pkey_negotiate(&c_channel, client_config.pkeyaccept, CLIENT)))
    {
        return 0;
    }

    if(!(client_config.kexkey_accept = kexkey_negotiate(&c_channel, client_config.kexkey_accept, CLIENT)))
    {
        return 0;
    }

    // FUTO
    if(channel_verify_finger_print(&c_channel, CLIENT, client_config.pkeyaccept) 
       == FINGER_PRINT_SAVED_FAILED)
    {
        fatal("Fail to save the finger print\n");
    }
    
    if( !public_key_authentication(&c_channel, 0, client_config.pkeyaccept) || 
        !public_key_authentication(&c_channel, 1, client_config.pkeyaccept))
    {
        fatal("Public key authentication failed\n");
    }

    // Trying to create a shared secret key
    if(!channel_generate_shared_key(&c_channel, ctx, client_config.kexkey_accept))
        fatal("Failed to create a shared secret key\n");

    // printf("RUNNIG\n");

    // password authentication successed, init channel_ctx
    channel_context_init(&channel_ctx, ctx, &d_channel, &c_channel, 
                         c_socket, d_socket, CLIENT, CLIENT_LOG);
    
    // perform password authentication
    password_authen_client(&c_channel, ctx);

    // Cancel alarm as all initial steps have been completed without any issue
    alarm(0);

    ftp_running = true;
    
    // trigger the alarm for idle timeout 
    signal(SIGALRM, time_out_alarm);
	alarm(client_config.idle_timeout);

    // Enter into ftp virtual environment
    while(ftp_running)
    {
        line = readline("ftp> ");

        if(!line) 
            break;

        // renew the alarm since the session is ative
        alarm(client_config.idle_timeout);

        // buffer = NULL;
        buffer = stripwhite(line);

        if(*buffer)
        {
            add_history (buffer);
            int operation_sucess = 1;
            get_cmd_contents(buffer, &cmd, &arg);

            if(arg)
            {
                channel_ctx.source = arg;
                channel_ctx.source_len = strlen(arg);
            }

            operation_sucess = run_command(&channel_ctx, cmd);

            if(!operation_sucess)
            {
                printf("Operation failed, see log in %s for more infos and retry\n", FTP_CLIENT_LOG_FILE);
                continue;
            }
            else 
            {
                printf("Operation Succeed \n");
            }

            if(channel_ctx.ret)
            {
                printf(GREEN);
                printf("%s\n", channel_ctx.ret);
                printf(RESET_COLOR);
                free(channel_ctx.ret);
                channel_ctx.ret = NULL;
            }

            if(channel_ctx.ret_int)
            {
                printf(GREEN);
                printf("%d\n", channel_ctx.ret_int);
                printf(RESET_COLOR);
                channel_ctx.ret_int = 0;
            }

        }        

        free (line);
    } 

    control_channel_destroy(&c_channel);

    // data channel managed dynamically by client, 
    // free here is nonsensical and could lead 
    // to segment fault
    // data_channel_destroy(&d_channel);
}
