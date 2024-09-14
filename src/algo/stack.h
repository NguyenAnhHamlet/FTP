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
bool is_stack_empty(Stack* s);
bool is_stack_full(Stack* s);
void init_stack(Stack* s);

#endif