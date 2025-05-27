#include "file.h"
#include<stdbool.h>
#include "common.h"
#include <unistd.h>
#include <sys/stat.h>
#include "log/ftplog.h"
#include <grp.h>
#include <pwd.h> 

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

static int permission_form(mode_t mode, char* permissions)
{
    permissions[0] = S_ISDIR(mode) ? 'd' : 
                    (S_ISCHR(mode) ? 'c' : (S_ISBLK(mode) ? 'b' : '-'));
    permissions[1] = (mode & S_IRUSR) ? 'r' : '-';
    permissions[2] = (mode & S_IWUSR) ? 'w' : '-';
    permissions[3] = (mode & S_IXUSR) ? 'x' : '-';
    permissions[4] = (mode & S_IRGRP) ? 'r' : '-';
    permissions[5] = (mode & S_IWGRP) ? 'w' : '-';
    permissions[6] = (mode & S_IXGRP) ? 'x' : '-';
    permissions[7] = (mode & S_IROTH) ? 'r' : '-';
    permissions[8] = (mode & S_IWOTH) ? 'w' : '-';
    permissions[9] = (mode & S_IXOTH) ? 'x' : '-';
    permissions[10] = ' ';
    return 1;
}

int ll_dir(const char* dir, char* res, unsigned int* r_len)
{
    DIR *d;
    struct dirent *ep;
    struct stat file_stat;
    struct passwd *pwd;
    struct group *grp;
    char full_path[1024];
    char time_str[80];
    char permissions[11];

    d = opendir(dir);
    if (d == NULL) 
    {
        perror("Couldn't open the directory");
        return 0;
    }

    while ((ep = readdir(d)) != NULL) 
    {
        if (ep->d_name[0] == '.' && (ep->d_name[1] == '\0' ||
            (ep->d_name[1] == '.' && ep->d_name[2] == '\0')))
            continue;

        snprintf(full_path, sizeof(full_path), "%s/%s", dir, ep->d_name);

        LOG(SERVER, "full_path: %s\n", full_path);

        if (stat(full_path, &file_stat) == -1) {
            perror("Error getting file status");
            return 0;
        }

        permission_form(file_stat.st_mode, permissions);
        pwd = getpwuid(file_stat.st_uid);
        grp = getgrgid(file_stat.st_gid);

        strftime(time_str, sizeof(time_str), "%b %e %H:%M", localtime(&file_stat.st_mtime));

        int snprintf_ret = snprintf(res + *r_len, 1024 - *r_len,
                                    "%s %2ld %-8s %-8s %8ld %s %s\n",
                                    permissions,
                                    file_stat.st_nlink,
                                    pwd ? pwd->pw_name : "",
                                    grp ? grp->gr_name : "",
                                    file_stat.st_size,
                                    time_str,
                                    ep->d_name);

        if (snprintf_ret < 0 || snprintf_ret >= (1024 - *r_len)) 
        {
            fprintf(stderr, "Buffer overflow or error during formatting.\n");
            return 0;
        }
        *r_len += snprintf_ret;
    }

    return 1;
} 