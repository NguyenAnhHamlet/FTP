Name: sftp
Version: 1.0.0 
Release: 1%{?dist}
Summary : Secure ftp client and secure ftp server 
License: GPLv2
Source0: %{name}-%{version}.tar.gz

Requires: bash gcc openssl openssl-devel readline readline-devel pam-devel 

%description
A secure remote file transfer client and server supporting a wide range of FTP-like commands for interacting.
It includes essential file operations and advanced features while utilizing strong encryption for 
secure communication.

%prep 
%setup -q  

%build 
make all 

%install 
mkdir -p %{buildroot}/%{_bindir}
mkdir -p %{buildroot}/etc/pam.d/
mkdir -p %{buildroot}/etc/ftp/
make DESTDIR=%{buildroot} install 

%files
%{_bindir}/ftpclient
%{_bindir}/ftpserver
%{_bindir}/ftpkeygen
/etc/ftp/sftp_config 
/etc/ftp/sftpd_config
/etc/pam.d/sftp

%changelog 
* Fri May 09 2025 Nguyen The Anh <sonate339@gmail.com> - 1.0.0 
- First version being package  
