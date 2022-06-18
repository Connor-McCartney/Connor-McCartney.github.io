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

I used [fcrackzip](https://github.com/hyc/fcrackzip) and rockyou:

<br>


