#include "queue.h"
#include <limits.h>

void init(Queue* queue)
{
    queue->capacity = queueSize;
    queue->front = queue->size = 0;
    queue->rear = queueSize - 1;
}

int isEmpty(Queue* queue)
{
    return (queue->size == 0);
}

int isFull(Queue* queue)
{
    return (queue->size == queue->capacity);
}

void enqueue(Queue* queue, int item)
{
    if (isFull(queue))
    return;
    queue->rear = (queue->rear + 1)
                  % queue->capacity;
    queue->data[queue->rear] = item;
    queue->size = queue->size + 1;
}

int dequeue(Queue* queue)
{
    if (isEmpty(queue))
    return INT_MIN;
    int item = queue->data[queue->front];
    queue->front = (queue->front + 1)
                   % queue->capacity;
    queue->size = queue->size - 1;
    return item;
}

int front(Queue* queue)
{
    if (isEmpty(queue))
    return INT_MIN;
    return queue->data[queue->front];
}

int rear(Queue* queue)
{
    if (isEmpty(queue))
    return INT_MIN;
    return queue->data[queue->rear];
}