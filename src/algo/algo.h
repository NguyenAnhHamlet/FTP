#ifndef __ALGO__
#define __ALGO__

#include <stdio.h>
#include <string.h>

char to_char(int num);
int to_int(char c);
int to_int(char num[], unsigned int size);
int max(int a, int b);
void upper_case_str(char* str, unsigned int str_len);
void lower_case_tr(char* str, unsigned int str_len);

#endif