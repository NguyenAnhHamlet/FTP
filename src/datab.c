#include "data.h"
#include "common/channel.h"
#include "common/file.h"
#include "cmd.h"
#include "common/ftp_type.h"
#include "common/packet.h"
#include "control.h"
#include <time.h>
#include "algo/algo.h"
#include "common/file.h"
#include "log/ftplog.h"
#include <glob.h>
#include <signal.h>
#include "datab.h"

extern int total_bytes;
static unsigned int* pipe_fd;

void data_signal_bget_handler(int signum) 
{
    char buf[BUF_LEN >> 2];
    sprintf(buf, "GET, ON GOING, TOTAL BYTES : %d", total_bytes);
    write(pipe_fd[1], buf, strlen(buf));
}

void data_signal_bput_handler(int signum) 
{
    char buf[BUF_LEN >> 2];
    sprintf(buf, "PUT, ON GOING, TOTAL BYTES : %d", total_bytes);
    write(pipe_fd[1], buf, strlen(buf));
}

void data_signal_bmget_handler(int signum) 
{
    char buf[BUF_LEN >> 2];
    sprintf(buf, "BMGET, ON GOING, TOTAL BYTES : %d", total_bytes);
    write(pipe_fd[1], buf, strlen(buf));
}

void data_signal_bmput_handler(int signum) 
{
    char buf[BUF_LEN >> 2];
    sprintf(buf, "BMPUT, ON GOING, TOTAL BYTES : %d", total_bytes);
    write(pipe_fd[1], buf, strlen(buf));
}

int bget(channel_context* channel_ctx)
{
    int ret = 0;
    pid_t pid;
    int free_pipe = get_free_pipe(channel_ctx);

    if(free_pipe < 0)
    {
        LOG(channel_ctx->log_type, "Reach MAXPROCCESS\n");
        return 0;
    }

    if(pipe(channel_ctx->pipe_fd[free_pipe]) == -1)
    {
        perror("Failed to create pipe fd\n");
        return 0;
    }

    
    pid = fork();
    if(pid < 0)
    {
        perror("Fork failed");
        return 0;
    }
    
    else if(pid == 0)
    {
        // set signal to interrupt, send back infos to parent process
        // Doing normal activities of get file 
        pipe_fd = channel_ctx->pipe_fd[free_pipe];
        signal(SIGUSR1, data_signal_bget_handler);
        ret = get(channel_ctx);
        close(pipe_fd[0]);
        close(pipe_fd[1]);
        return ret;
    }

    else 
    {
        channel_ctx->usedpipe[free_pipe] = pid;
    }

    return 1;
}

int bput(channel_context* channel_ctx)
{
    int ret = 0;
    pid_t pid;
    int free_pipe = get_free_pipe(channel_ctx);

    if(free_pipe < 0)
    {
        LOG(channel_ctx->log_type, "Reach MAXPROCCESS\n");
        return 0;
    }

    if(pipe(channel_ctx->pipe_fd[free_pipe]) == -1)
    {
        perror("Failed to create pipe fd\n");
        return 0;
    }

    pid = fork();
    if(pid < 0)
    {
        perror("Fork failed");
        return 0;
    }

    else if(pid == 0)
    {
        // set signal to interrupt, send back infos to parent process
        // Doing normal activities of put file 
        signal(SIGUSR1, data_signal_bput_handler);
        ret = put(channel_ctx);
        close(pipe_fd[0]);
        close(pipe_fd[1]);
        return ret;
    }

    else 
    {
        channel_ctx->usedpipe[free_pipe] = pid;
    }

    return 1;
}

int bmget(channel_context* channel_ctx)
{
    int ret = 0;
    pid_t pid;
    int free_pipe = get_free_pipe(channel_ctx);

    if(free_pipe < 0)
    {
        LOG(channel_ctx->log_type, "Reach MAXPROCCESS\n");
        return 0;
    }

    if(pipe(channel_ctx->pipe_fd[free_pipe]) == -1)
    {
        perror("Failed to create pipe fd\n");
        return 0;
    }

    pid = fork();
    if(pid < 0)
    {
        perror("Fork failed");
        return 0;
    }

    else if(pid == 0)
    {
        // set signal to interrupt, send back infos to parent process
        // Doing normal activities of mget file 
        signal(SIGUSR1, data_signal_bmget_handler);
        ret = mget(channel_ctx);
        close(pipe_fd[0]);
        close(pipe_fd[1]);
        return ret;
    }

    else 
    {
        channel_ctx->usedpipe[free_pipe] = pid;
    }

    return 1;
}

int bmput(channel_context* channel_ctx)
{
    int ret = 0;
    pid_t pid;
    int free_pipe = get_free_pipe(channel_ctx);

    if(free_pipe < 0)
    {
        LOG(channel_ctx->log_type, "Reach MAXPROCCESS\n");
        return 0;
    }

    if(pipe(channel_ctx->pipe_fd[free_pipe]) == -1)
    {
        perror("Failed to create pipe fd\n");
        return 0;
    }

    pid = fork();
    if(pid < 0)
    {
        perror("Fork failed");
        return 0;
    }

    else if(pid == 0)
    {
        // set signal to interrupt, send back infos to parent process
        // Doing normal activities of get file 
        signal(SIGUSR1, data_signal_bmput_handler);
        ret = mput(channel_ctx);
        close(pipe_fd[0]);
        close(pipe_fd[1]);
        return ret;
    }

    else 
    {
        channel_ctx->usedpipe[free_pipe] = pid;
    }

    return 1;
}