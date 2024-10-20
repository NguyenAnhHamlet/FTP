#ifndef __FILE_CUS__
#define __FILE_CUS__

#include<stdio.h>
#include<string.h>
#include<stdbool.h>
#include <dirent.h>
#include <sys/stat.h>

void read_file(char path[], FILE* fp);
void write_file(char path[], char data[],FILE* fp);
mode_t permission(char path[]);      
void create_file(char path[]);
void append_file(char path[], char data[], int data_size);
bool not_exist(char path[]);
int list_dir(char* dir, char* res, unsigned int* r_len);
void delete_file(char path[]);

// NOTICE: only deallocate path when ret is no longer needed
void basename(char* path, char** ret);

#endif