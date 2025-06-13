#include "timer.h"
#include "common.h"
#include <pthread.h>
#include <semaphore.h>

void init_timer_semaphore(timer* timer) 
{
    sem_init(&timer->timerSemaphore, 0, 2); 
}

void wait_timer_semaphore(timer* timer) 
{
    sem_wait(&timer->timerSemaphore);
}

void signal_timer_semaphore(timer* timer) 
{
    sem_post(&timer->timerSemaphore);
}

int start_timer(timer* timer, callbackFunc func)
{
    if(!timer) return Faillure;

    wait_timer_semaphore(timer);

    timer->in_used++;
    timer->running = 1;
    timer->current_time = time(NULL);

    delay_timer(timer);

    if(timer->running) func(timer);

    timer->running = 0;

    timer->in_used--;

    signal_timer_semaphore(timer);
}

void* timer_thread_wrapper(void* arg) 
{
    TimerThreadArgs* args = (TimerThreadArgs*)arg; 
    start_timer(args->timer, args->func);
    return NULL;
}

int start_timerThread(TimerThreadArgs* args, timer* timer, 
                      callbackFunc func)
{
    pthread_t thread;
    args->timer = timer;
    args->func = func;
    pthread_create(&thread, NULL, timer_thread_wrapper, args);
}

int cancel_timer(timer* timer)
{
    if(!timer) return Faillure;

    timer->running = 0;

    while(timer->in_used);

    free(timer);
}

int cancel_timer_thread(TimerThreadArgs* arg)
{
    if(!arg) return Faillure;
    cancel_timer(arg->timer);
    free(arg);
}

int delay_timer(timer* timer)
{
    if(!timer) return Faillure;
    wait_timer_semaphore(timer);
    timer->in_used++;

    while(timer->running && 
        (int) difftime(timer->current_time, timer->start_time) 
        >= timer->due_time);

    timer->in_used--;
    signal_timer_semaphore(timer);

    return Success;
}

void set_timer(timer* timer, time_t start , time_t end)
{
    if(!timer) return 
    timer->in_used++;
    timer->current_time = time(NULL);
    timer->start_time = start;
    timer->due_time = end;
    timer->running = 0;
    timer->in_used--;
}