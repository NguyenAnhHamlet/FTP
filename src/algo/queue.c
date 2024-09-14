#include "queue.h"
#include <limits.h>

void init_queue(Queue* queue)
{
    queue->capacity = queueSize;
    queue->front = queue->size = 0;
    queue->rear = queueSize - 1;
}

int queue_is_empty(Queue* queue)
{
    return (queue->size == 0);
}

int queue_is_full(Queue* queue)
{
    return (queue->size == queue->capacity);
}

void enqueue(Queue* queue, int item)
{
    if (queue_is_full(queue))
    return;
    queue->rear = (queue->rear + 1)
                  % queue->capacity;
    queue->data[queue->rear] = item;
    queue->size = queue->size + 1;
}

int dequeue(Queue* queue)
{
    if (queue_is_empty(queue))
    return INT_MIN;
    int item = queue->data[queue->front];
    queue->front = (queue->front + 1)
                   % queue->capacity;
    queue->size = queue->size - 1;
    return item;
}

int front(Queue* queue)
{
    if (queue_is_empty(queue))
    return INT_MIN;
    return queue->data[queue->front];
}

int rear(Queue* queue)
{
    if (queue_is_empty(queue))
    return INT_MIN;
    return queue->data[queue->rear];
}