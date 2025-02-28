#include "cmd.h"
#include "data.h"
#include "control.h"
#include "datab.h"

command commands[] = {
    {"get", 500, get, "get file from remote server. Usage: get <remote file name>"},
    {"put", 501, put, "send file to remote server. Usage: put <local file name>"},
    {"append", 502, data_append, "append a local file to remote file on server." 
                                 "Usage: append <local file name> <remote file name>"},
    {"lcd", 503, local_change_dir, "change local path. Usage: lcd <local path>"},
    {"cd", 504, remote_change_dir, "change remote path. Usage: cd <remote path>"},
    {"chmod", 505, change_mode, "change file/dir mode on remote server. Usage: chmod <remote file/path>"},
    {"delete", 506, delete_remote_file, "delete remote file on server. Usage: delete <remote file>"},
    {"dir", 507, list_remote_dir, "list remote dir. Usage: ls <remote dir>"},
    {"!ls", 508, list_local_dir, "list local dir. Usage: ls <local dir>"},
    {"ls", 509, list_remote_dir, "list remote dir. Usage: ls <remote dir>"},                        // TODO : list additional infos
    {"idle", 510, idle_set_remote, "set idle time out. Usage: idle <time out value>"},              // TODO: set timeout on server for the session
    {"mdelete", 511, mdelte_remote_files, "delete multiple remote file on server. Usage: mdelete <remote file>"},
    {"mmkdir", 512, remote_mmkdir, "make multiple dirs on remote server. Usage: mmkdir <dir1 dir2 ...>" },
    {"mget", 513, mget, "get multiple files from remote server. Usage: mget <file1 file2 ...> "},
    {"mkdir", 514, remote_mkdir, "mkdir on remote server. Usage: mkdir <dir1 dir2 ...>"},
    {"mls", 515, mlist_remote_dir, "list multiple remote dir on server. Usage <dir1 dir2 file1 file2 ...>"},
    {"modtime", 516, remote_modtime, "get remote modtime. Usage: modtime"},
    {"mput", 517, mput, "put multiple files to remote server. Usage: mput <file1 file2 file3 ...>"},
    {"newer", 518, data_newer, "If local file is older, get the file from remote. Usage: newer <file>"},
    {"nlist", 519, list_remote_dir, "list only name of file in remote dir. Usage: ls <remote dir>"},
    {"prompt", 520, local_prompt, "set to 1 enable prompt, 0 disable it. Usgae: prompt <0/1>"},                                                                          // TODO: prompt 0 : not asking, prompt 1: asking
    {"pwd", 521, remote_pwd, "remote pwd. Usage: pwd"},
    {"reget", 522, data_reget, "reget the file from the latest cursor position. Usage: reget <remote file name>"},
    {"rename", 523, remote_change_name, "change remote file name. Usage: rename <old name> <new name>"},                                                                    // TODO: display bytes counter
    {"restart", 524, restart_get_file, "restart the get from bytes. Usage: restart <name> <bytes> "},                        
    {"rmdir", 525, remove_remote_dir, "remove remote dir. Usage: rmdir <remote dir>"},
    {"size", 526, remote_get_size, "get remote file's size. Usage: size <remote file>"},
    {"stat", 527, status, "status of file, folder, local. Usage: rstatus || rstatus <file> || rstatus <folder>"},
    {"system", 528, remote_system_info, "remote system infos. Usage: system"},
    {"ipv4_op", 529, NULL},
    {"ipv6_op", 530, NULL},
    {"passmode", 531, passmode, "Switch to passive mode (connect to server in passive mode). Usage: passmode"},
    // {"bget", 532, bget, "run get file from remote server in the bg. Usage: get <remote file name>"},
    // {"bput", 533, bput, "run send file to remote server in the bg. Usage: put <local file name>"},
    // {"bmget", 534, bmget, "run get multiple files from remote server in the bg. Usage: mget <file1 file2 ...> "},
    // {"bmput", 535, bmput, "run put multiple files to remote server in the bg. Usage: mput <file1 file2 file3 ...>"},
    {"mmkdir", 536, remote_mmkdir, "multiple mkdir on remote server. Usage: mkdir <dir1 dir2 ...>"},
    {"!pwd", 537, local_pwd, "local pwd. Usage: !pwd"},
    { NULL, 0, NULL, NULL }
};

int islocal_func(unsigned int code)
{
    if(code == STATUS) return 1;
    if(code == LCD) return 1;
    if(code == LLS) return 1;

    return 0;
}


