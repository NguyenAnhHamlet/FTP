#include "file.h"
#include<stdbool.h>
#include "common.h"
#include <unistd.h>
#include <sys/stat.h>
#include "log/ftplog.h"

void read_file(char path[], FILE* fp)
{
    if(not_exist(path)) fatal("File does not exist\n");

    fp = fopen(path, "r");

    if(!fp) fatal("Could not create file descriptor\n");
}

void write_file(char path[], char data[], FILE* fp)
{
    fp = fopen(path, "wb");

    if(!fp) fatal("Could not create file descriptor\n");

    fprintf(fp, "%s", data);

    fclose(fp);

}

mode_t permission(char path[])
{
    if(not_exist(path)) fatal("File does not exist\n");

    struct stat stat_result;
    if (stat(path, &stat_result) == -1) fatal("Error in stat");

    mode_t permissions = stat_result.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO);

    return permissions;
}   

void create_file(char path[])
{
    FILE* fp = fopen(path, "w");
    fclose(fp);
}


void delete_file(char path[])
{
    remove(path);
}


void append_file(char path[], char data[], int data_size)
{
    FILE* fp = fopen(path, "a");

    if(!fp) fatal("Could not create file descriptor\n");

    int bytes_written = fwrite(data, sizeof(char), data_size, fp);

    fclose(fp);

    if(bytes_written != data_size)
    {
        perror("Write operation failed\n");
    }
}

bool is_empty(char path[], FILE* fp)
{
    fp = fopen(path, "r");
    char buffer[1];

    size_t bytes_read = fread(buffer, 1, 1, fp);

    fclose(fp);

    if(bytes_read) return false;

    return true;
}

bool not_exist(char path[])
{
    if(access(path, F_OK) == -1) return true;

    return false;
}

int list_dir(char* dir, char* res, unsigned int* r_len)
{
    DIR *d;
    struct dirent *ep; 
    struct stat file_stat; 

    d = opendir(dir);

    if (d == NULL) 
    {
        perror("Couldn't open the directory");
        return 0;
    }

    if (d != NULL)
    {
        while ((ep = readdir (d)) != NULL)
        {
            if (ep->d_name[0] == '.' && (ep->d_name[1] == '\0' || 
                (ep->d_name[1] == '.' && ep->d_name[2] == '\0')))
                continue;
            strncat(res, ep->d_name, sizeof(ep->d_name));
            strncat(res, " \n", 2);
            *r_len += sizeof(ep->d_name);
            *r_len +=2;
        }
    }

    (void) closedir(d);

    return 1;
}

void basename(char* path, char** ret)
{
    *ret = strrchr(path, '/');

    if (!*ret)
    {
        *ret = path;
        return;
    }

    (*ret)++; 
}