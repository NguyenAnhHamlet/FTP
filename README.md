# Secure Remote File Transfer Client  

## Overview  
A secure remote file transfer client and server supporting a wide range of FTP-like commands for interacting. It includes essential file operations and advanced features while utilizing strong encryption for secure communication.  

## Features  

### File Operations  
- **File Transfer:** `get`, `put`, `append`, `mget`, `mput`, `reget`  
- **Directory Management:** `mkdir`, `rmdir`, `mmkdir`  
- **File & Directory Listings:** `ls`, `dir`, `mls`, `nlist`  
- **File Deletion & Renaming:** `delete`, `mdelete`, `rename`  
- **Metadata Operations:** `size`, `modtime`, `stat`, `newer`  

### Navigation Commands  
- **Local Navigation:** `lcd`, `!ls`, `!pwd`  
- **Remote Navigation:** `cd`, `pwd`  

### Session Management & Settings  
- **Idle Timeout:** `idle`  
- **Prompt Mode:** `prompt` (enable/disable command confirmation)  
- **Passive Mode Switching:** `passmode`  

### Security & Encryption  
- **Public Key Algorithms:** `ED25519`, `RSA`  
- **Key Exchange Algorithms:** `DH`, `ECDH`  

## Installation  

To build and install the client, run:  
```sh
make all       # Compile the client and server
make install   # Install the client and server
