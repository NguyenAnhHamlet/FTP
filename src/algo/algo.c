#include "algo/algo.h"
#include <ctype.h>
#include <ctype.h>
#include <time.h>

char to_char(int num)
{
    return num +0;
}

int char_to_int(char c)
{
    return c - '0';
}

int str_to_int(char num[], unsigned int size)
{
    int res = 0;
    for(int i= 0; i < size; i++)
    {
        res *= 10;
        res += char_to_int(num[i]);
    }

    return res;
}

int max(int a, int b)
{
    return a > b ? a : b;                               
}

int min(int a, int b)
{
    return a < b ? a : b;
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

int convert_to_datetime(char* org, struct tm* datetime)
{
    return strptime(org, "%Y-%m-%d %H:%M:%S", datetime) != NULL;
}

bool is_older(struct tm* datetime_1, struct tm* datetime_2)
{
    time_t time_1, time_2;

    time_1 = mktime(datetime_1);
    time_2 = mktime(datetime_2);

    return time_1 < time_2;
}

unsigned int find_index(char* str, unsigned int str_len, char c)
{
    for(int i=0; i< str_len; i++)
    {
        if(str[i] == c) 
            return i;
    }

    return 0;
}

void remove_endline(char* str)
{
    unsigned int len = strlen(str);
    if(str[len-1] == '\n') 
        str[len-1] = '\0'; 
}