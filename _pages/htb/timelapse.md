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

Note the SMB protocol - we can enumerate it with [smbmap](https://github.com/ShawnDEvans/smbmap):

