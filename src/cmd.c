#include "cmd.h"
#include "data.h"
#include "control.h"
#include "datab.h"

command commands[] = {
    {"get", 500, get, "get file from remote server. Usage: get <remote file name>"},
    {"put", 501, put, "send file to remote server. Usage: put <local file name>"},
    {"append", 502, data_append, "append a local file to remote file on server." 
                                 "Usage: append <local file name> <remote file name>"},
    {"lcd", 503, local_change_dir, "change local path. Usage: cd <local path>"},
    {"cd", 504, remote_change_dir, "change remote path. Usage: cd <remote path>"},
    {"chmod", 505, change_mode, "change file/dir mode on remote server. Usage: chmod <remote file/path>"},
    {"delete", 505, delete_remote_file, "delete remote file on server. Usage: delete <remote file>"},
    {"dir", 507, list_remote_dir, "list remote dir. Usage: ls <remote dir>"},
    {"!ls", 508, list_local_dir, "list local dir. Usage: ls <local dir>"},
    {"ls", 509, list_remote_dir, "list remote dir. Usage: ls <remote dir>"},                        // TODO : list additional infos
    {"idle", 510, idle_set_remote, "set idle time out. Usage: idle <time out value>"},              // TODO: set timeout on server for the session
    {"mdelete", 511, mdelte_remote_files, "delete multiple remote file on server. Usage: mdelete <remote file>"},
    {"mdir", 512, remote_mmkdir, "make multiple dirs on remote server. Usage: mdir <dir1 dir2 ...>" },
    {"mget", 515, mget, "get multiple files from remote server. Usage: mget <file1 file2 ...> "},
    {"mkdir", 516, remote_mkdir, "mkdir on remote server. Usage: mkdir <dir1 dir2 ...>"},
    {"mls", 517, mlist_remote_dir, "list multiple remote dir on server. Usage <dir1 dir2 file1 file2 ...>"},
    {"modtime", 518, remote_modtime, "get remote modtime. Usage: modtime"},
    {"mput", 519, mput, "put multiple files to remote server. Usage: mput <file1 file2 file3 ...>"},
    {"newer", 520, data_newer, "If local file is older, get the file from remote. Usage: newer <file>"},
    {"nlist", 521, list_remote_dir, "list only name of file in remote dir. Usage: ls <remote dir>"},
    {"prompt", 522, local_prompt, "set to 1 enable prompt, 0 disable it. Usgae: prompt <0/1>"},                                                                          // TODO: prompt 0 : not asking, prompt 1: asking
    {"pwd", 523, remote_pwd, "remote pwd. Usage: pwd"},
    {"reget", 525, data_reget, "reget the file from the latest cursor position. Usage: reget <remote file name>"},
    {"rename", 526, remote_change_name, "change remote file name. Usage: rename <old name> <new name>"},                                                                    // TODO: display bytes counter
    {"restart", 528, restart_get_file, "restart the get from bytes. Usage: restart <name> <bytes> "},                                 // Restart from bytes
    {"rmdir", 530, remove_remote_dir, "remove remote dir. Usage: rmdir <remote dir>"},
    {"size", 532, remote_get_size, "get remote file's size. Usage: size <remote file>"},
    {"stat", 533, status, "status of file, folder, local. Usage: rstatus || rstatus <file> || rstatus <folder>"},
    {"system", 534, remote_system_info, "remote system infos. Usage: system"},
    {"ipv4_op", 536, NULL},
    {"ipv6_op", 537, NULL},
    {"passmode", 538, passmode, "Switch to passive mode (connect to server in passive mode). Usage: passmode"},
    {"bget", 539, bget, "run get file from remote server in the bg. Usage: get <remote file name>"},
    {"bput", 540, bput, "run send file to remote server in the bg. Usage: put <local file name>"},
    {"bmget", 541, bmget, "run get multiple files from remote server in the bg. Usage: mget <file1 file2 ...> "},
    {"bmput", 542, bmput, "run put multiple files to remote server in the bg. Usage: mput <file1 file2 file3 ...>"},
    { NULL, NULL, NULL }
};


