#ifndef __TIMER__
#define __TIMER__

#include <stdio.h>
#include <time.h>
#include <pthread.h>
#include <semaphore.h>

typedef struct Timer
{
    time_t start_time; 
    time_t current_time;
    time_t due_time;
    pthread_mutex_t timerMutex;
    sem_t timerSemaphore;

    int running;
    int in_used;
} Timer;

typedef struct {
  Timer* timer;
  callbackFunc func;
  unsigned int socketfd;
} TimerThreadArgs;

typedef void (*callbackFunc)(Timer*);

// Use semaphore to prevent user from setting the timer 
// value start_time and current time during the function startTimer 
// which could cause the timer to run forever 
void initTimerSemaphore(Timer* timer);
void waitTimerSemaphore(Timer* timer);
void signalTimerSemaphore(Timer* timer);

void setTimer(Timer* timer, time_t start , time_t end);

// after done running, the func shall be called
int startTimer(Timer* timer, callbackFunc func);

void* timerThreadWrapper(void* arg);
int startTimerThread(TimerThreadArgs* arg ,Timer* timer, callbackFunc func);

// in_used variable help to keep track of the object timer
// if none of the thread / function is using this object
// cancelTimer could destroy it
int cancelTimer(Timer* timer);
int cancelTimerThread(TimerThreadArgs* arg);
int delayTimer(Timer* timer);

#endif