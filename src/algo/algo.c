#include "algo.h"
#include <ctype.h>
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
int convert_to_datetime(char* org, struct tm* datetime)
{
    return strptime(org, "%Y-%m-%d %H:%M:%S", datetime) != NULL;
}

bool is_older(struct tm* datetime_1, struct tm* datetime_2)
{
    time_t time_1, time_2;

    time_1 = mktime(datetime_1);
    time_2 = mktime(datetime_2);

    return time_1 > time_2;
}