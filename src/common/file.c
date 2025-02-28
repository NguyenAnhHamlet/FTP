#include "file.h"
#include<stdbool.h>
#include "common.h"
#include <unistd.h>
#include <sys/stat.h>
#include "log/ftplog.h"

int read_file(const char* path, FILE** fp)
{
    if(not_exist(path))
    {
        perror("File does not exist");
        return 0;
    }     

    *fp = fopen(path, "r");

    if(!*fp)
    {
        perror("Could not create file descriptor");
        return 0;
    } 
}

void write_file(const char* path, char data[], FILE* fp)
{
    fp = fopen(path, "wb");

    if(!fp) perror("Could not create file descriptor");

    fprintf(fp, "%s", data);

    fclose(fp);

}

mode_t permission(const char* path)
{
    if(not_exist(path)) 
    {
        perror("File does not exist");
        return -1;
    }

    struct stat stat_result;
    if (stat(path, &stat_result) == -1)
    {
        perror("Error in stat");
        return -1;
    } 
        
    mode_t permissions = stat_result.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO);

    return permissions;
}   

int create_file(const char* path)
{
    FILE* fp = fopen(path, "w");
    if(!fp) return 0;
    fclose(fp);
    return 1;
}


void delete_file(const char* path)
{
    remove(path);
}


int append_file(const char* path, char data[], int data_size)
{
    FILE* fp = fopen(path, "ab");

    if(!fp)
    {
        perror("Could not create file descriptor");
        return 0;
    } 

    int bytes_written = fwrite(data, sizeof(char), data_size, fp);

    fclose(fp);

    if(bytes_written != data_size)
    {
        perror("Write operation failed");
        return 0;
    }

    return 1;
}

bool is_empty(const char* path, FILE* fp)
{
    fp = fopen(path, "r");
    char buffer[1];

    size_t bytes_read = fread(buffer, 1, 1, fp);

    fclose(fp);

    if(bytes_read) return false;

    return true;
}

bool not_exist(const char* path)
{
    if(access(path, F_OK) == -1) return true;

    return false;
}

int list_dir(const char* dir, char* res, unsigned int* r_len)
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
            *r_len += strlen(ep->d_name);
            *r_len +=2;
        }
    }

    (void) closedir(d);

    return 1;
}

void basename(const char* path, char** ret)
{
    *ret = strrchr(path, '/');

    if (!*ret)
    {
        *ret = path;
        return;
    }

    (*ret)++; 
}

int change_dir(const char* path)
{
    if(chdir(path) < 0)
    {
        perror("Fail to change directory");
        return -1;
    }

    return 1;
}

int directory_exists(const char *path) 
{
    struct stat st;

    if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) 
    {
        return 1;
    }
    return 0; 
}