#include "stack.h"
#include <limits.h>

int top(Stack* s)
{
    if(isEmpty(s)) return INT_MIN;

    return s->data[s->total];
}

int pop(Stack* s)
{
    if(isEmpty(s)) return INT_MIN;

    int topVal = top(s);
    s->data[s->total] = -1;
    s->total--;

    return topVal;
}

int push(Stack* s, int val)
{
    s->total++;
    s->data[s->total] = val;
}

bool isEmpty(Stack* s)
{
    if(s->total < 0) return true;

    return false;
}

bool isFull(Stack* s)
{
    if(s->total == sizeStack -1) return true;

    return false;
}

void init(Stack* s)
{
    s->total = -1;
}