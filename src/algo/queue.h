#ifndef __STACK__
#define __STACK__

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#define queueSize 2056

typedef struct Queue
{
    int front, rear, size;
    unsigned capacity;
    int data[queueSize];
} Queue;

void init_queue(Queue* queue);
int queue_is_empty(Queue* queue);
int queue_is_full(Queue* queue);
void enqueue(Queue* queue, int item);
int dequeue(Queue* queue);
int front(Queue* queue);
int rear(Queue* queue);

#endif