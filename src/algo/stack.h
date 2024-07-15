#ifndef __STACK__
#define __STACK__

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#define sizeStack 2056

typedef struct Stack
{
    int data[2056];
    int total;
} Stack;

int top(Stack* s);
int pop(Stack* s);
int push(Stack* s, int val);
bool isEmpty(Stack* s);
bool isFull(Stack* s);
void init(Stack* s);

#endif