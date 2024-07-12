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
<<<<<<< HEAD
void append_file(char path[], char data[]);
=======
void append_file(char path[], char data[], FILE* fp);
>>>>>>> 14a728ce950b1f1d31e5c2ca3e3777f82f231bd5
bool is_empty(char path[], FILE* fp);
bool not_exist(char path[]);

#endif