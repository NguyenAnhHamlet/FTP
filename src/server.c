#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h> 
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
#include "algo/algo.h"

extern command commands[];
socket_ftp* socket_server;

static struct 
{
    unsigned int pkeyaccept;
    unsigned int kexkey_accept;
    unsigned int rlogin;
    unsigned int maxauth;
    unsigned int passauth;
    unsigned int dataport;
    unsigned int controlport;
    unsigned int addrfamily;
    unsigned int idle_tmout;
} server_config;

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
    {"DataPort", DataPort},
    {NULL, 0}
};

static struct {
    control_channel c_channel; 
    data_channel d_channel;
    cipher_context* ctx;
    int time_out;
    int conn_remain;
    unsigned request_int;
    bool operation_sucess;
    socket_ftp* d_socket;
    socket_ftp* c_socket;
    channel_context channel_ctx;
    fd_set read_set;
    unsigned int clientfd;
} ftp_server_session;

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
                server_config.dataport = str_to_int(cp, strlen(cp));
                printf("%d\n", server_config.dataport);
                break;
            }
            case DataPort:
            {
                cp = strtok(NULL, WHITESPACE);
                printf("%s\n", cp);
                server_config.controlport = str_to_int(cp, strlen(cp));
                printf("%d\n", server_config.controlport);
                break;
            }
        }
    }

    return 1;
}

void signal_handler(int sig)
{
    LOG(SERVER_LOG, "Received signal %d; terminating.\n", sig);
    close(socket_server->sockfd);
    exit(255);
}

void time_out_alarm(int sig)
{
    LOG(SERVER_LOG, "Time out\n");
    exit(1);
}

void idle_timeout_hdl(int sig)
{
    LOG(SERVER_LOG, "Idle time out\n");
    shutdown(ftp_server_session.clientfd, SHUT_RDWR);
    exit(1);
}

int pass_authen_server(control_channel* c_channel, cipher_context *ctx)
{
    struct passwd* pw = NULL;
    char user_name[BUF_LEN];
    char user_pass[BUF_LEN];
    char *user_pass_dec, *name_dec;
    int len;

restart:
    server_config.maxauth--;
    if(control_channel_read_expect(c_channel, FTP_PASS_AUTHEN) <= 0)
    {
        LOG(SERVER_LOG, "Failed receive infos name\n");
        return 0;
    }

    len = control_channel_get_data_len_in(c_channel);
    control_channel_get_str(c_channel, user_name, &len);
    name_dec = (char*) malloc(len);
    aes_cypher_decrypt(ctx, user_name, len, name_dec, &len);

    if(control_channel_read_expect(c_channel, FTP_PASS_AUTHEN) <= 0)
    {
        LOG(SERVER_LOG, "Failed receive infos pass\n");
        return 0;
    }

    len = control_channel_get_data_len_in(c_channel);
    control_channel_get_str(c_channel, user_pass, &len);
    user_pass_dec = (char*) malloc(len);
    aes_cypher_decrypt(ctx, user_pass, len, user_pass_dec, &len);

    pw = getpwnam(name_dec);

    if (!pw )
    {
        LOG(SERVER_LOG, "Athentication failed for user %s", name_dec);

        if(server_config.maxauth > 0)
        {
            control_channel_append_ftp_type(FTP_AUTHEN_RETRY, c_channel);
            control_channel_send_wait(c_channel);
            goto restart;
        }
        else
        {
            control_channel_append_ftp_type(FTP_NACK, c_channel);
            control_channel_send_wait(c_channel);
            return 0;
        }        
    }

    // prevent user with root privileges
    if(!server_config.rlogin && pw->pw_uid == 0 )
    {
        LOG(SERVER_LOG, "User %s is stopped due to having root privileges\n", name_dec);
        control_channel_append_ftp_type(FTP_ROOT_DENY, c_channel);
        control_channel_send(c_channel);
        return 0;
    }

    start_pam(pw);

    if( auth_pam_password(pw, user_pass_dec))
    {
        control_channel_append_ftp_type(FTP_ACK, c_channel);
        control_channel_send_wait(c_channel);
    }
    else if(server_config.maxauth)
    {
        control_channel_append_ftp_type(FTP_AUTHEN_RETRY, c_channel);
        control_channel_send_wait(c_channel);
        printf("Fail \n");
        server_config.maxauth--;
        goto restart;
    }
    else
    {
        control_channel_append_ftp_type(FTP_NACK, c_channel);
        control_channel_send_wait(c_channel);
        return 0;
    }

    return 1;
}

int run_command(channel_context* channel_ctx, unsigned int code)
{
    // Some unique base case
    if(code == GET) code = PUT;
    else if(code == PUT) code = GET;

    for(int i =0; commands[i].command_str != NULL; i++)
    {
        if(commands[i].command_code == code)
        {
            return commands[i].func(channel_ctx);
        }
    }

    return 0;
}

int main()
{
    bool isRunning = 1;
    int pid, newsock;
    unsigned int maxClientSocket = 0;
    unsigned int clientfd;
    fd_set readfds;
    int activity;
    int activity_client;
    pthread_t pub_key_thread;
    char buf[BUF_LEN];
    char conf[] = "/etc/ftp/sftpd_config";

    read_config(conf);

    // init
    ftp_server_session.channel_ctx.control_port = server_config.controlport;
    ftp_server_session.channel_ctx.data_port = server_config.dataport;
    socket_server = create_ftp_socket(NULL, AF_INET, SERVER, 
                                      ftp_server_session.channel_ctx.control_port, 
                                      SERVER_LISTENING, 
                                      cre_socket());

    // signal and handle
    signal(SIGINT, signal_handler);
    signal(SIGQUIT, signal_handler);
    signal(SIGTERM, signal_handler);

    while(isRunning)
    {
        // add server socket
        FD_ZERO(&readfds);
        FD_SET(socket_server->sockfd, &readfds);

        activity = select(socket_server->sockfd + 1, &readfds, NULL, NULL, NULL);

        if ((activity < 0) && (errno != EINTR)) 
            perror("select error");

        if (FD_ISSET(socket_server->sockfd, &readfds))
        {
            newsock = accept_new_connection_ftp(socket_server);

            if(newsock < 0 )
            {
                if (errno != EINTR && errno != EWOULDBLOCK)
                {
                    perror("Accept error\n");
                }

                continue;
            }

            if (fcntl(newsock, F_SETFL, 0) < 0) 
            {
                perror("newsock del O_NONBLOCK: %s");
                continue;	
            }

            maxClientSocket = max(newsock, maxClientSocket);

            // New connection from client
            // Fork to form a new process
            if ((pid = fork()) == 0) 
            {
                clientfd = newsock ;
                LOG(SERVER_LOG, "New connection from client with fd: %d\n", clientfd);
                break;
            } 
        }
    }

    // Client process handle
    // init
    ftp_server_session.ctx = (cipher_context*) malloc(sizeof(cipher_context));
    ftp_server_session.c_socket = socket_ftp_raw_cre();
    ftp_server_session.time_out = 30 * 60;
    ftp_server_session.conn_remain = 1;
    ftp_server_session.operation_sucess = 1;

    ftp_socket_cp(ftp_server_session.c_socket, socket_server);
    control_channel_init(&ftp_server_session.c_channel, clientfd, clientfd, SERVER, NULL);
    ftp_server_session.clientfd = clientfd;
    
    signal(SIGALRM, time_out_alarm);
	alarm(30);

    if(!(server_config.pkeyaccept = pkey_negotiate(&ftp_server_session.c_channel, server_config.pkeyaccept, SERVER)))
    {
        return 0;
    }

    if(!(server_config.kexkey_accept = kexkey_negotiate(&ftp_server_session.c_channel, server_config.kexkey_accept, SERVER)))
    {
        return 0;
    }

    // FUTO
    LOG(SERVER_LOG, "HERE 0 p : %d\n",server_config.pkeyaccept );

    if(channel_verify_finger_print(&ftp_server_session.c_channel, SERVER, server_config.pkeyaccept) 
       == FINGER_PRINT_SAVED_FAILED)
    {
        LOG(SERVER_LOG, "Client did not accept finger print\n");
        exit(1);
    }

    if(!public_key_authentication(&ftp_server_session.c_channel, 1, server_config.pkeyaccept)|| 
       !public_key_authentication(&ftp_server_session.c_channel, 0, server_config.pkeyaccept))
    {
        LOG(SERVER_LOG, "Pub authen failed with socket %d\n", 
            ftp_server_session.c_channel.data_in->in_port);
        exit(1);
    }

    // cipher context init for dec/enc of data channel
    aes_cipher_init(ftp_server_session.ctx);

    // Trying to create a shared secret key
    if(!channel_generate_shared_key(&ftp_server_session.c_channel, 
                                    ftp_server_session.ctx, 
                                    server_config.kexkey_accept))
        fatal("Failed to create a shared secret key\n");


    // init channel_ctx
    channel_context_init(&ftp_server_session.channel_ctx, ftp_server_session.ctx, 
                         &ftp_server_session.d_channel, &ftp_server_session.c_channel, 
                         ftp_server_session.c_socket, ftp_server_session.d_socket, 
                         SERVER, SERVER_LOG);

    // if(!pass_authen_server(&ftp_server_session.c_channel, ftp_server_session.ctx))
    //     exit(1);
    
    // Cancel alarm as all initial steps are done without issue
    alarm(0);

    signal(SIGALRM, idle_timeout_hdl);
    alarm(server_config.idle_tmout);

    while(ftp_server_session.conn_remain)
    {
        FD_ZERO(&ftp_server_session.read_set);
        FD_SET(ftp_server_session.c_channel.data_in->in_port, 
               &ftp_server_session.read_set);
        select(ftp_server_session.c_channel.data_in->in_port + 1, 
               &ftp_server_session.read_set, NULL, NULL, NULL);

        if(control_channel_read_expect(&ftp_server_session.c_channel, TERMINATE))
        {
            LOG(SERVER_LOG, "Terminate connection with client fd %d", clientfd);
            exit(1);
        }

        ftp_server_session.request_int = control_channel_get_ftp_type_in(&ftp_server_session.c_channel);

        ftp_server_session.operation_sucess = run_command(&ftp_server_session.channel_ctx, 
                                                          ftp_server_session.request_int);

        if(!ftp_server_session.operation_sucess)
            LOG(SERVER_LOG, "Operation failed\n");
        alarm(server_config.idle_tmout);
    }
    
    return 0;
}