#include "file.h"
#include<stdbool.h>
#include "common.h"
#include <unistd.h>
#include <sys/stat.h>

void read_file(char path[], FILE* fp)
{
    if(not_exist(path)) fatal("File does not exist\n");

    fp = fopen(path, "r");

    if(!fp) fatal("Could not create file descriptor\n");
}

void write_file(char path[], char data[], FILE* fp)
{
    FILE* fp = popen();

    fp = fopen(path, "wb");

    if(!fp) fatal("Could not create file descriptor\n");

    fprintf(fp, data);
<<<<<<< HEAD

    fclose(fp);
=======
<<<<<<< HEAD

    fclose(fp);
=======
>>>>>>> 14a728ce950b1f1d31e5c2ca3e3777f82f231bd5
>>>>>>> bad9d9234c108c8a8e237bdaa51e6b43677a4e18
}

mode_t permission(char path[])
{
    if(not_exist(path)) fatal("File does not exist\n");

    struct stat stat_result;
    if (stat(path, &stat_result) == -1) fatal("Error in stat");

    mode_t permissions = stat_result.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO);

    return permissions;
}   

void create_file(char path[], FILE* fp)
{
    fp = fopen(path, "w");
<<<<<<< HEAD
    fclose(fp);
=======
<<<<<<< HEAD
    fclose(fp);
=======
>>>>>>> 14a728ce950b1f1d31e5c2ca3e3777f82f231bd5
>>>>>>> bad9d9234c108c8a8e237bdaa51e6b43677a4e18
}

void delete_file(char path[])
{
    remove(path);
}

<<<<<<< HEAD
void append_file(char path[], char data[])
{
    FILE* fp;
    
=======
<<<<<<< HEAD
void append_file(char path[], char data[])
=======
void append_file(char path[], char data[],FILE* fp)
>>>>>>> 14a728ce950b1f1d31e5c2ca3e3777f82f231bd5
{
>>>>>>> bad9d9234c108c8a8e237bdaa51e6b43677a4e18
    fp = fopen(path, "a");

    if(!fp) fatal("Could not create file descriptor\n");

    fprintf(fp, data);
<<<<<<< HEAD

    fclose(fp);
=======
<<<<<<< HEAD

    fclose(fp);
=======
>>>>>>> 14a728ce950b1f1d31e5c2ca3e3777f82f231bd5
>>>>>>> bad9d9234c108c8a8e237bdaa51e6b43677a4e18
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