#ifndef __FILE_CUS__
#define __FILE_CUS__

#include<stdio.h>
#include<string.h>
#include<stdbool.h>
#include <dirent.h>
#include <sys/stat.h>

#define CHMOD_755(file) chmod(file, 0755)
#define CHMOD_644(file) chmod(file, 0644)
#define CHMOD_640(file) chmod(file, 0600)

int read_file(const char* path, FILE** fp);
void write_file(const char* path, char data[], FILE* fp);
mode_t permission(const char* path);      
int create_file(const char* path);
int append_file(const char* path, char data[], int data_size);
bool not_exist(const char* path);
int list_dir(const char* dir, char* res, unsigned int* r_len);
void delete_file(const char* path);
int change_dir(const char* path);
int directory_exists(const char *path);

// NOTICE: only deallocate path when ret is no longer needed
void basename(const char* path, char** ret);

// ls -l in bash 
int ll_dir(const char* dir, char** res, unsigned int* r_len);

#endif