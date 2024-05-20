#include "algo.h"

char tochar(int num)
{
    return num +0;
}

int toint(char c)
{
    return (int)(c);
}

int toInt(char num[], unsigned int size)
{
    int res = 0;
    for(int i= 0; i < size; i++)
    {
        res *= 10;
        res += toint(num[i]);
    }

    return res;
}

int max(int a, int b)
{
    return a > b ? a : b;
}