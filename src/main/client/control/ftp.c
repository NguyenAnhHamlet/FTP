#include "ftp.h"
#include "send.h"
#include "establish.h"
#include "common.h"
#include <stdbool.h>
#include <stdlib.h>
#include "send.h"
#include "secure.h"
#include "timer.h"
#include <time.h>
#include <signal.h>

void time_out_alarm(int sig)
{
    errorLog("Time out");
}

void splitArgs(_socketFTP* socketFTP, int argc, ...)
{
    va_list ptr;

    va_start(ptr, argc);
    char* arg = va_arg(ptr, char*);
    strcpy(socketFTP->ip_addr, arg);

    for(int i =1; i < argc; i++)
    {
        arg = va_arg(ptr, char*);
        if(!handleOp(socketFTP, arg)) errorLog("Faillure in handle options\n"); 
    }
}

// Client side functions
int quit() 
{
  // Implement quit function here
}

int help() 
{
  // Implement help function here
}

int ascii() 
{
  // Implement ascii function here
}

int bell() 
{
  // Implement bell function here
}

int binary() 
{
  // Implement binary function here
}

int bye() 
{
  // Implement bye function here (might be same as quit)
}

int close() 
{
  // Implement close function here
}

int cr() 
{
  // Implement cr function here
}

int debug() 
{
  // Implement debug function here
}

int disconnect() 
{
  // Implement disconnect function here
}

int exit_cmd() 
{
  // Implement exit_cmd function here (might be same as quit)
}

int form() 
{
  // Implement form function here
}

int glob() 
{
  // Implement glob function here
}

int hash() 
{
  // Implement hash function here
}

int help_client() 
{
  // Implement help_client function here
}

int image() 
{
  // Implement image function here
}

int macdef() 
{
  // Implement macdef function here
}

int verbose() 
{
  // Implement verbose function here
}

int umask() 
{
  // Implement umask function here
}

// Data command functions
int get() 
{
  // Implement get function here
}

int put() 
{
  // Implement put function here
}

int recv() 
{
  // Implement recv function here (might be similar to get)
}

int send() 
{
  // Implement send function here (might be similar to put)
}

void ipv4_op(_socketFTP* socketFTP)
{
    socketFTP->endpoint_addr->sin_family = AF_INET;
}

void ipv6_op(_socketFTP* socketFTP)
{
    socketFTP->endpoint_addr->sin_family = AF_INET6;
}

void passmode(_socketFTP* socketFTP)
{
    socketFTP->op |= PASSIVE_MODE;
}

void int_off(_socketFTP* socketFTP)
{
    socketFTP->op &= ~INTERACTIVE_MODE;
}

void aulog_dis(_socketFTP* socketFTP)
{
    socketFTP->op &= ~AUTO_LOGGIN;
}

void glob_dis(_socketFTP* socketFTP)
{
   socketFTP->op &= ~NAME_GLOBBING;
}

void verbose_enb(_socketFTP* socketFTP)
{
    socketFTP->op |= VERBOSE_OUTPUT;
}

void debug_enb(_socketFTP* socketFTP)
{
    socketFTP->op |= DEBUG_ENB_OP;
}

int sendClientRequest(char req[], Asym_Infos* as_infos, Timer* timer)
{
    if(!timer) return Faillure;

    setTimer(timer, time(NULL), 10);

    startTimer(timer, callBackTimer);

    if(!send_msg(as_infos->setupSocket, BUF_LEN, req)) return Faillure;

    cancelTimer(timer);

    return Success;
}

int handleRequest(char req[], Asym_Infos* as_infos, Timer* timer)
{
    int res = Faillure;

    if (strcmp(req, QUIT) == 0) return quit();
    else if (strcmp(req, HELP) == 0) return help();
    else if (strcmp(req, ASCII) == 0) return ascii();
    else if (strcmp(req, BELL) == 0) return bell();
    else if (strcmp(req, BINARY) == 0) return binary();
    else if (strcmp(req, BYE) == 0) return bye();
    else if (strcmp(req, CLOSE) == 0) return close_cmd();
    else if (strcmp(req, CR) == 0) return cr();
    else if (strcmp(req, DEBUG) == 0) return debug();
    else if (strcmp(req, DISCONNECT) == 0) return disconnect();
    else if (strcmp(req, EXIT) == 0) return exit_cmd();
    else if (strcmp(req, FORM) == 0) return form();
    else if (strcmp(req, GLOB) == 0) return glob();
    else if (strcmp(req, HASH) == 0) return hash();
    else if (strcmp(req, HELP_CLIENT) == 0) return help_client();
    else if (strcmp(req, IMAGE) == 0) return image();
    else if (strcmp(req, MACDEF) == 0) return macdef();
    else if (strcmp(req, VERBOSE) == 0) return verbose();
    else if (strcmp(req, UMASK) == 0) return umask();

    return Faillure;
}

int recvServerReply(char rep[], Asym_Infos* as_infos, Timer* timer)
{
      
}

int handleReply(char rep[], Asym_Infos* as_infos, Timer* timer)
{

}

int handleOp(_socketFTP* socketFTP, char op[])
{
    if(strcmp(op, IPV4_OP))         ipv4_op(socketFTP);
    else if(strcmp(op, IPV6_OP))    ipv6_op(socketFTP);
    else if(strcmp(op, PASSMODE))   passmode(socketFTP);
    else if(strcmp(op, INT_OFF))    int_off(socketFTP);
    else if(strcmp(op, AULOG_DIS))  aulog_dis(socketFTP);
    else if(strcmp(op, GLOB_DIS))   glob_dis(socketFTP);
    else if(strcmp(op, VER_OUT))    verbose_enb(socketFTP);
    else if(strcmp(op, DEBUG_ENB))  debug_enb(socketFTP);
    else                            return Faillure;

    return Success;
}

void callBackTimer(Timer* timer)
{
    errorLog("Time out\n");
}

int main(int argc, char* argvs[])
{
    Asym_Infos as_infos;
    TimerThreadArgs *arg = (TimerThreadArgs*) malloc(sizeof(TimerThreadArgs));
    Timer* pubAuthentimer = (Timer*) malloc(sizeof(Timer));
    char option[8];
    char ipaddr[32];
    char buffer[BUF_LEN];
    unsigned int iptype;
    bool FTPrunning;

    // Create a FTP socket
    _socketFTP* socketFTP = cre_FTPSocket(ipaddr, iptype, CLIENT);
    
    // public key authen 
    as_infos.setupSocket = socketFTP->sockfd;
    as_infos.conn = CLIENT;

    // set alarm for 30 seconds
    signal(SIGALRM, time_out_alarm);
		alarm(30);

    if(!public_key_Authentication(&as_infos))
        errorLog("Public key authentication failed\n");
    
    // recv the respond about pubkey authen from server
    recvmsg(as_infos.setupSocket, buffer, 0);

    if(strcmp(buffer, PUB_AUTHEN_FAIL)) 
        errorLog("Public key authentication failed\n");

    // Pub authen done successfully, cancel alarm
    alarm(0);

    FTPrunning = true;

    // Enter into ftp virtual environment
    while(FTPrunning)
    {
        printf("ftp> ");
        fgets(buffer, sizeof(buffer), stdin);
        handleRequest(buffer, &as_infos, (Timer*) malloc(sizeof(Timer)));
    } 
}