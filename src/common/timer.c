#include "timer.h"
#include "common.h"
#include <pthread.h>
#include <semaphore.h>

void initTimerSemaphore(Timer* timer) 
{
    sem_init(&timer->timerSemaphore, 0, 2); 
}

void waitTimerSemaphore(Timer* timer) 
{
    sem_wait(&timer->timerSemaphore);
}

void signalTimerSemaphore(Timer* timer) 
{
    sem_post(&timer->timerSemaphore);
}

int startTimer(Timer* timer, callbackFunc func)
{
    if(!timer) return Faillure;

    waitTimerSemaphore(timer);

    timer->in_used++;
    timer->running = 1;
    timer->current_time = time(NULL);

    delayTimer(timer);

    if(timer->running) func(timer);

    timer->running = 0;

    timer->in_used--;

    signalTimerSemaphore(timer);
}

void* timerThreadWrapper(void* arg) 
{
    TimerThreadArgs* args = (TimerThreadArgs*)arg; 
    startTimer(args->timer, args->func);
    return NULL;
}

int startTimerThread(TimerThreadArgs* args, Timer* timer, callbackFunc func)
{
    pthread_t thread;
    args->timer = timer;
    args->func = func;
    pthread_create(&thread, NULL, timerThreadWrapper, args);
}

int cancelTimer(Timer* timer)
{
    if(!timer) return Faillure;

    timer->running = 0;

    while(timer->in_used);

    free(timer);
}

int cancelTimerThread(TimerThreadArgs* arg)
{
    if(!arg) return Faillure;
    cancelTimer(arg->timer);
    free(arg);
}

int delayTimer(Timer* timer)
{
    if(!timer) return Faillure;

    waitTimerSemaphore(timer);

    timer->in_used++;

    while(timer->running && (int) difftime(timer->current_time, timer->start_time) >= timer->due_time);

    timer->in_used--;

    signalTimerSemaphore(timer);

    return Success;
}

void setTimer(Timer* timer, time_t start , time_t end)
{
    if(!timer) return Faillure;

    timer->in_used++;

    timer->current_time = time(NULL);
    timer->start_time = start;
    timer->due_time = end;
    timer->running = 0;

    timer->in_used--;
}