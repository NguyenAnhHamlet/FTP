#!/bin/bash

if [[ $# -eq 0 ]]; then
  echo "Error: Please provide an IP address."
  exit 1
fi

if [[ $# -gt 1 ]]; then
  echo "Warning: Only the last argument will be considered as the IP address."
fi

# check for key file
if [ !find /etc/pub/ -name *.key -o !find /etc/priv/ -name *] ; then 
    echo "Please generate pair key file"
    exit 1
fi

IP="${@: -1}"
OPTIONS="${@: 0: $# }"
FTP_BIN=/usr/bin/ftp

if [ !-f ${FTP_BIN} ] ; then 
    echo "There is no ftpserver"
    exit 1
fi

function __checkIP()
{
    regexIP=[1-9][0-9]{2}.\d{1,3}.\d{1,3}.\d{1,3}

    local IP="$1"

    if [${IP} =~ !${regexIP}] ; then 
        echo "IP address is unidentified"
        exit 1
    fi

}

function __main()
{
    __checkIP ${IP}
    /usr/bin/ftp ${OPTIONS} ${IP}
}



__main



