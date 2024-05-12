#ifndef __FILE_CUS__
#define __FILE_CUS__

#include<stdio.h>
#include<string.h>
#include<stdbool.h>

void readFile(char path[], FILE* fp);
void writeFile(char path[], char data[],FILE* fp);
mode_t permission(char path[]);      
void createFile(char path[], FILE* fp);
void deleteFile(char path[]);
void appendFile(char path[], char data[], FILE* fp);
bool isEmpty(char path[], FILE* fp);
bool notExist(char path[]);

#endif