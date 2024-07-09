#ifndef __FILE_CUS__
#define __FILE_CUS__

#include<stdio.h>
#include<string.h>
#include<stdbool.h>

void read_file(char path[], FILE* fp);
void write_file(char path[], char data[],FILE* fp);
mode_t permission(char path[]);      
void create_file(char path[], FILE* fp);
void delete_file(char path[]);
void append_file(char path[], char data[], FILE* fp);
bool is_empty(char path[], FILE* fp);
bool not_exist(char path[]);

#endif