#include "algo.h"
#include <ctype.h>

char to_char(int num)
{
    return num +0;
}

int to_int(char c)
{
    return (int)(c);
}

int to_int(char num[], unsigned int size)
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

void upper_case_str(char* str, unsigned int str_len)
{
    for(int i=0; i < str_len; ++i)
    {
        str[i] = toupper(str[i]);
    }
}

void lower_case_tr(char* str, unsigned int str_len)
{
    for(int i=0; i < str_len; ++i)
    {
        str[i] = tolower(str[i]);
    }
}