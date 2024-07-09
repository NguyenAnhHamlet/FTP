#ifndef __TIMER__
#define __TIMER__

#include <stdio.h>
#include <time.h>
#include <pthread.h>
#include <semaphore.h>

typedef struct
{
    time_t start_time; 
    time_t current_time;
    time_t due_time;
    pthread_mutex_t timerMutex;
    sem_t timerSemaphore;

    int running;
    int in_used;
} timer;

typedef struct {
  timer* timer;
  callbackFunc func;
  unsigned int socketfd;
} TimerThreadArgs;

typedef void (*callbackFunc)(timer*);

// Use semaphore to prevent user from setting the timer 
// value start_time and current time during the function start_timer 
// which could cause the timer to run forever 
void init_timer_semaphore(timer* timer);
void wait_timer_semaphore(timer* timer);
void signal_timer_semaphore(timer* timer);

void set_timer(timer* timer, time_t start , time_t end);

// after done running, the func shall be called
int start_timer(timer* timer, callbackFunc func);

void* timer_thread_wrapper(void* arg);
int start_timer_thread(TimerThreadArgs* arg ,timer* timer, callbackFunc func);

// in_used variable help to keep track of the object timer
// if none of the thread / function is using this object
// cancel_timer could destroy it
int cancel_timer(timer* timer);
int cancel_timer_thread(TimerThreadArgs* arg);
int delay_timer(timer* timer);

#endif