#include "file.h"
#include<stdbool.h>
#include "common.h"
#include <unistd.h>
#include <sys/stat.h>

void readFile(char path[], FILE* fp)
{
    if(notExist(path)) errorLog("File does not exist\n");

    fp = fopen(path, "r");

    if(!fp) errorLog("Could not create file descriptor\n");
}

void writeFile(char path[], char data[], FILE* fp)
{
    FILE* fp = popen();

    fp = fopen(path, "wb");

    if(!fp) errorLog("Could not create file descriptor\n");

    fprintf(fp, data);
}

mode_t permission(char path[])
{
    if(notExist(path)) errorLog("File does not exist\n");

    struct stat stat_result;
    if (stat(path, &stat_result) == -1) errorLog("Error in stat");

    mode_t permissions = stat_result.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO);

    return permissions;
}   

void createFile(char path[], FILE* fp)
{
    fp = fopen(path, "w");
}

void deleteFile(char path[])
{
    remove(path);
}

void appendFile(char path[], char data[],FILE* fp)
{
    fp = fopen(path, "a");

    if(!fp) errorLog("Could not create file descriptor\n");

    fprintf(fp, data);
}

bool isEmpty(char path[], FILE* fp)
{
    fp = fopen(path, "r");
    char buffer[1];

    size_t bytes_read = fread(buffer, 1, 1, fp);

    if(bytes_read) return false;

    return true;
}

bool notExist(char path[])
{
    if(access(path, F_OK) == -1) return true;

    return false;
}