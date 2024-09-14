#ifndef __ALGO__
#define __ALGO__

#define _XOPEN_SOURCE 

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>

char to_char(int num);
int char_to_int(char c);
int str_to_int(char num[], unsigned int size);
int max(int a, int b);
void upper_case_str(char* str, unsigned int str_len);
void lower_case_tr(char* str, unsigned int str_len);
int convert_to_datetime(char* org, struct tm* datetime);
bool is_older(struct tm* datetime_1, struct tm* datetime_2);
void upper_case_str(char* str, unsigned int str_len);
void lower_case_tr(char* str, unsigned int str_len);

#endif