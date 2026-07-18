---
permalink: /misc/OverTheWireBandit
title: OverTheWire - Bandit
---

<br>

<br>



<https://overthewire.org/wargames/bandit/bandit0.html>


<br>


Current as of July 2026

<br>

<br>



# 0 to 1


```bash
bandit0@bandit:~$ ls
readme
bandit0@bandit:~$ cat readme 
Congratulations on your first steps into the bandit game!!
Please make sure you have read the rules at https://overthewire.org/rules/
If you are following a course, workshop, walkthrough or other educational activity,
please inform the instructor about the rules as well and encourage them to
contribute to the OverTheWire community so we can keep these games free!

The password you are looking for is: 6y2kwnwK6grgvwvpvLaa2T1cpFEKOhNR

bandit0@bandit:~$
```


<br>



# 1 to 2


```bash
bandit1@bandit:~$ ls
-
bandit1@bandit:~$ cat ./-
PK8fYLZg2hnHSz83plBL1iEPKdD3QToB
```


<br>



# 2 to 3


```bash
bandit2@bandit:~$ ls
--spaces in this filename--
bandit2@bandit:~$ cat ./"--spaces in this filename--"
7ZZ2LFrykP2zEyvBl4m3clcL7tGYJPME
```


<br>




# 3 to 4


```bash
$ ssh bandit3@bandit.labs.overthewire.org -p 2220

bandit3@bandit:~$ ls
inhere
bandit3@bandit:~$ cd inhere/
bandit3@bandit:~/inhere$ ls -a
.  ..  ...Hiding-From-You
bandit3@bandit:~/inhere$ cat ...Hiding-From-You 
xzTXq1rDJQVVAzdv5cHq1TQytTWufAMq
```


<br>














# 4 to 5


```bash
bandit4@bandit:~$ ls
inhere

bandit4@bandit:~$ cd inhere

bandit4@bandit:~/inhere$ ls
-file00  -file01  -file02  -file03  -file04  -file05  -file06  -file07  -file08  -file09

bandit4@bandit:~/inhere$ file ./*
./-file00: data
./-file01: data
./-file02: OpenPGP Secret Key
./-file03: data
./-file04: data
./-file05: data
./-file06: Non-ISO extended-ASCII text, with NEL line terminators
./-file07: ASCII text
./-file08: data
./-file09: data

bandit4@bandit:~/inhere$ cat ./-file07
6C7h9GD8M6ai5nr7wo1RonrzFjj9yIrG

```


<br>













# 5 to 6


```bash
bandit5@bandit:~$ cat $(find . -size 1033c)
pXa26xhMWaC2SvDotA4r9EgZkulOeSBW
```


<br>












# 6 to 7


```bash
bandit6@bandit:~$ cat $(find / -size 33c -user bandit7 -group bandit6 2>/dev/null)
Bmnnvf82KzQlfxgAI2d1zYbr1u9pr3E3
```


<br>













# 7 to 8


```bash
bandit7@bandit:~$ grep millionth data.txt 
millionth	VR1ljMayciFxbnUokuQmJFw6QC9VKtub
```


<br>












# 8 to 9


```bash
bandit8@bandit:~$ sort data.txt | uniq -u
EjmOSvuAu7sGAHqHVcBDPirRe9T03kxl
```


<br>













# 9 to 10


```bash
bandit9@bandit:~$ strings data.txt | grep ===
========== the
========== password
Y========== is
========== B0s2khmbT9u0geKuOoVGW3JZKhndE3BG
```


<br>








# 10 to 11


```bash
bandit10@bandit:~$ base64 -d data.txt 
The password is pYfOY6HwUsDj5rL9UvyhU7MCmv8vN5Ro
```


<br>







# 11 to 12


g? in vim :)

```
The password is GROozWPO8QyN0mGrjUkID0WCYkZiQxrN

```


<br>










# 12 to 13


```bash
bandit12@bandit:~$ ls
data.txt

bandit12@bandit:~$ mktemp -d
/tmp/tmp.hC18RPEq7B

bandit12@bandit:~$ cp data.txt /tmp/tmp.hC18RPEq7B

bandit12@bandit:~$ cd /tmp/tmp.hC18RPEq7B

bandit12@bandit:/tmp/tmp.hC18RPEq7B$ xxd -r data.txt > 1


bandit12@bandit:/tmp/tmp.hC18RPEq7B$ file 1
1: gzip compressed data, was "data2.bin", last modified: Wed Jun 24 14:58:46 2026, max compression, from Unix, original size modulo 2^32 580
bandit12@bandit:/tmp/tmp.hC18RPEq7B$ gunzip -c 1 > 2


bandit12@bandit:/tmp/tmp.hC18RPEq7B$ file 2
2: bzip2 compressed data, block size = 900k
bandit12@bandit:/tmp/tmp.hC18RPEq7B$ bzip2 -d -c 2 > 3


bandit12@bandit:/tmp/tmp.hC18RPEq7B$ file 3
3: gzip compressed data, was "data4.bin", last modified: Wed Jun 24 14:58:46 2026, max compression, from Unix, original size modulo 2^32 20480
bandit12@bandit:/tmp/tmp.hC18RPEq7B$ gunzip -c 3 > 4


bandit12@bandit:/tmp/tmp.hC18RPEq7B$ file 4
4: POSIX tar archive (GNU)
bandit12@bandit:/tmp/tmp.hC18RPEq7B$ tar -xf 4 -O > 5 


bandit12@bandit:/tmp/tmp.hC18RPEq7B$ file 5
5: POSIX tar archive (GNU)
bandit12@bandit:/tmp/tmp.hC18RPEq7B$ tar -xf 5 -O > 6


bandit12@bandit:/tmp/tmp.hC18RPEq7B$ file 6
6: bzip2 compressed data, block size = 900k
bandit12@bandit:/tmp/tmp.hC18RPEq7B$ bzip2 -d -c 6 > 7


bandit12@bandit:/tmp/tmp.hC18RPEq7B$ file 7
7: POSIX tar archive (GNU)
bandit12@bandit:/tmp/tmp.hC18RPEq7B$ tar -xf 7 -O > 8


bandit12@bandit:/tmp/tmp.hC18RPEq7B$ file 8
8: gzip compressed data, was "data9.bin", last modified: Wed Jun 24 14:58:46 2026, max compression, from Unix, original size modulo 2^32 49
bandit12@bandit:/tmp/tmp.hC18RPEq7B$ gunzip -c 8 > 9


bandit12@bandit:/tmp/tmp.hC18RPEq7B$ file 9
9: ASCII text
bandit12@bandit:/tmp/tmp.hC18RPEq7B$ cat 9
The password is qQYQiHOBPR8zR61qxYqX45quvihF2uzk



```


<br>















# 13 to 14


```bash

[~/t] 
$ scp -P 2220 bandit13@bandit.labs.overthewire.org:/home/bandit13/sshkey.private  .
                         _                     _ _ _   
                        | |__   __ _ _ __   __| (_) |_ 
                        | '_ \ / _` | '_ \ / _` | | __|
                        | |_) | (_| | | | | (_| | | |_ 
                        |_.__/ \__,_|_| |_|\__,_|_|\__|
                                                       

                      This is an OverTheWire game server. 
            More information on http://www.overthewire.org/wargames

backend: gibson-1
bandit13@bandit.labs.overthewire.org's password: 
sshkey.private                                                                              100% 2602     2.7KB/s   00:00 


[~/t] 
$ chmod 600 sshkey.private 

[~/t] 
$ ssh bandit14@bandit.labs.overthewire.org -p 2220 -i sshkey.private 
bandit14@bandit:~$ 


```


<br>











# 14 to 15


```bash
bandit14@bandit:~$ cat /etc/bandit_pass/bandit14 | nc localhost 30000                           
Correct!
pbLYuZtTg4MgaqfJx8jbA9gKKGqM68A7
```


<br>










# 15 to 16


```bash
bandit15@bandit:~$ openssl s_client 127.0.0.1:30001         
---
read R BLOCK
pbLYuZtTg4MgaqfJx8jbA9gKKGqM68A7
Correct!
kS0Hf0u5HiXFwKMKFqXvPdOTNGGa0X8V

closed


```


<br>

Alternative:

```python
import socket
import ssl

HOST = '127.0.0.1'
PORT = 30001

context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

with socket.create_connection((HOST, PORT)) as sock:
    with context.wrap_socket(sock, server_hostname=HOST) as ssock:

        ssock.sendall(b'pbLYuZtTg4MgaqfJx8jbA9gKKGqM68A7'+ b'\n')

        response = ssock.recv(1024)
        print(response.decode())
```

<br>


```
bandit15@bandit:/tmp/tmp.9wnMsk3KK5$ python3 solve.py 
Correct!
kS0Hf0u5HiXFwKMKFqXvPdOTNGGa0X8V
```


<br>









# 16 to 17


```bash
bandit16@bandit:~$ nmap -sV localhost -p 31000-32000
Starting Nmap 7.98 ( https://nmap.org ) at 2026-07-16 22:03 +0000
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00016s latency).
Other addresses for localhost (not scanned): ::1
Not shown: 996 closed tcp ports (conn-refused)
PORT      STATE SERVICE     VERSION
31046/tcp open  echo
31518/tcp open  ssl/echo
31691/tcp open  echo
31790/tcp open  ssl/unknown
31960/tcp open  echo


bandit16@bandit:~$ cat /etc/bandit_pass/bandit16                                             
kS0Hf0u5HiXFwKMKFqXvPdOTNGGa0X8V




bandit16@bandit:~$ openssl s_client -connect 127.0.0.1:31790 -ign_eof
Connecting to 127.0.0.1
CONNECTED(00000003)

<...>

---
read R BLOCK
kS0Hf0u5HiXFwKMKFqXvPdOTNGGa0X8V
Correct!
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----

closed
bandit16@bandit:~$ 
```


<br>





# 17 to 18


```bash
bandit17@bandit:~$ diff passwords.old  passwords.new 
42c42
< qOg5pVOjPx9x9VccyYBADiT4xxyoUB8D
---
> OQxXZjELndr90zuhOTDYBEomI0SZITXI
```


<br>





# 18 to 19


```bash
$ ssh bandit18@bandit.labs.overthewire.org -p 2220 /bin/bash
                         _                     _ _ _   
                        | |__   __ _ _ __   __| (_) |_ 
                        | '_ \ / _` | '_ \ / _` | | __|
                        | |_) | (_| | | | | (_| | | |_ 
                        |_.__/ \__,_|_| |_|\__,_|_|\__|
                                                       

                      This is an OverTheWire game server. 
            More information on http://www.overthewire.org/wargames

backend: gibson-1
bandit18@bandit.labs.overthewire.org's password: 



ls
readme
cat readme
KpsOfPkcP7i1FlIExk2QEjyt6dw8dxZI
```


<br>





# 19 to 20


```bash
bandit19@bandit:~$ ./bandit20-do cat /etc/bandit_pass/bandit20
4pIjcunZ0fK2vmp3IwfG8Vf7VhxD6pOA
```


<br>





# 20 to 21

```bash
bandit20@bandit:~$ ./suconnect 1234
Read: 4pIjcunZ0fK2vmp3IwfG8Vf7VhxD6pOA
Password matches, sending next password
bandit20@bandit:~$ 
```

<br>

```bash
bandit20@bandit:~$ nc -lvnp 1234
Listening on 0.0.0.0 1234
Connection received on 127.0.0.1 41510
4pIjcunZ0fK2vmp3IwfG8Vf7VhxD6pOA
bW9kBv5WC3P4yoDyf12LSdGuNz5ka6hY
bandit20@bandit:~$ 
```


<br>





# 21 to 22


```bash
bandit21@bandit:~$ cd /etc/cron.d/

bandit21@bandit:/etc/cron.d$ ls
behemoth4_cleanup  cronjob_bandit22  cronjob_bandit24  leviathan5_cleanup    otw-tmp-dir
clean_tmp          cronjob_bandit23  e2scrub_all       manpage3_resetpw_job

bandit21@bandit:/etc/cron.d$ cat cronjob_bandit22
@reboot bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
* * * * * bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null

bandit21@bandit:/etc/cron.d$ cat /usr/bin/cronjob_bandit22.sh
#!/bin/bash
chmod 644 /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
cat /etc/bandit_pass/bandit22 > /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv

bandit21@bandit:/etc/cron.d$ cat /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
RYVux2rHEm9tiXHmLFzuR7Vhx6AZQMEz
```


<br>





# 22 to 23


```bash
bandit22@bandit:~$ cd /etc/cron.d/

bandit22@bandit:/etc/cron.d$ ls
behemoth4_cleanup  cronjob_bandit22  cronjob_bandit24  leviathan5_cleanup    otw-tmp-dir
clean_tmp          cronjob_bandit23  e2scrub_all       manpage3_resetpw_job

bandit22@bandit:/etc/cron.d$ cat cronjob_bandit23
@reboot bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null
* * * * * bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null

bandit22@bandit:/etc/cron.d$ cat /usr/bin/cronjob_bandit23.sh
#!/bin/bash

myname=$(whoami)
mytarget=$(echo I am user $myname | md5sum | cut -d ' ' -f 1)

echo "Copying passwordfile /etc/bandit_pass/$myname to /tmp/$mytarget"

cat /etc/bandit_pass/$myname > /tmp/$mytarget


bandit22@bandit:/etc/cron.d$ echo I am user bandit23 | md5sum | cut -d ' ' -f 1
8ca319486bfbbc3663ea0fbe81326349

bandit22@bandit:/etc/cron.d$ cat /tmp/8ca319486bfbbc3663ea0fbe81326349
gKXDTAXnIz3OBxiPjRZ2uqutUlPZrBsw
```


<br>





# 23 to 24


```bash
bandit23@bandit:/etc/cron.d$ ls
behemoth4_cleanup  cronjob_bandit22  cronjob_bandit24  leviathan5_cleanup    otw-tmp-dir
clean_tmp          cronjob_bandit23  e2scrub_all       manpage3_resetpw_job


bandit23@bandit:/etc/cron.d$ cat cronjob_bandit24
@reboot bandit24 /usr/bin/cronjob_bandit24.sh &> /dev/null
* * * * * bandit24 /usr/bin/cronjob_bandit24.sh &> /dev/null


bandit23@bandit:/etc/cron.d$ cat /usr/bin/cronjob_bandit24.sh
#!/bin/bash

shopt -s nullglob

myname=$(whoami)

cd /var/spool/"$myname"/foo || exit 
echo "Executing and deleting all scripts in /var/spool/$myname/foo:"
for i in * .*;
do
    if [ "$i" != "." ] && [ "$i" != ".." ];
    then
        echo "Handling $i"
        owner="$(stat --format "%U" "./$i")"
        if [ "${owner}" = "bandit23" ] && [ -f "$i" ]; then
            timeout -s 9 60 "./$i"
        fi
        rm -rf "./$i"
    fi
```


<br>



```bash
bandit23@bandit:~$ mktemp -d
/tmp/tmp.N97JqEluou
bandit23@bandit:~$ chmod o+wx /tmp/tmp.N97JqEluou
bandit23@bandit:~$ printf "cat /etc/bandit_pass/bandit24 > /tmp/tmp.N97JqEluou/password" > /var/spool/bandit24/foo/x.sh  
bandit23@bandit:~$ chmod o+x /var/spool/bandit24/foo/x.sh
bandit23@bandit:~$ # wait up to 1 minute for the cronjob to execute
bandit23@bandit:~$ cat /tmp/tmp.N97JqEluou/password
hVQMk3lJNsmQ7VF3ubyrNNBom7BOgVXv
```

<br>





# 24 to 25


```python
import socket

socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.connect(("127.0.0.1", 30002))

socket.recv(1024)
for pin in range(10000):
    socket.sendall((f'hVQMk3lJNsmQ7VF3ubyrNNBom7BOgVXv {pin:04d}\n').encode())
    response = socket.recv(1024)
    print(f'{pin:04d} {response}')
    if b'Wrong' not in response:
        break
```


```
...
0328 b'Wrong! Please enter the correct current password and pincode. Try again.\n'
0329 b'Wrong! Please enter the correct current password and pincode. Try again.\n'
0330 b'Wrong! Please enter the correct current password and pincode. Try again.\n'
0331 b'Wrong! Please enter the correct current password and pincode. Try again.\n'
0332 b'Correct!\nThe password of user bandit25 is SoHfqMOEqIX2IYKVciZxvgpR9a2Djx4P\n\n'
```




<br>






# 25 to 26


```bash
bandit25@bandit:~$ grep bandit26 /etc/passwd 
bandit26:x:11026:11026:bandit level 26:/home/bandit26:/usr/bin/showtext

bandit25@bandit:~$ cat /usr/bin/showtext
#!/bin/sh

export TERM=linux

exec more ~/text.txt
exit 0

bandit25@bandit:~$ ls
bandit26.sshkey
```




```bash
$ chmod 600 bandit26.sshkey 
$ ssh bandit26@bandit.labs.overthewire.org -p 2220 -i bandit26.sshkey
```



Make your teminal very small so more goes into command mode. 

press 'v' to open vim

then in vim:

```
:set shell=/bin/bash
:shell
bandit26@bandit:~$ cat /etc/bandit_pass/bandit26
jHdv2ELQhT22BkprMNDjybZDAkw1zeBJ
```


<br>






# 26 to 27



```bash
bandit26@bandit:~$ ls
bandit27-do  text.txt

bandit26@bandit:~$ ./bandit27-do 
Run a command as another user.
  Example: ./bandit27-do id

bandit26@bandit:~$ ./bandit27-do cat /etc/bandit_pass/bandit27
STJLJBRRphMxKB392CT4iOr5CbzPU9ER
```


<br>






# 27 to 28




```bash

[~/t] 
$ git clone ssh://bandit27-git@bandit.labs.overthewire.org:2220/home/bandit27-git/repo 
Cloning into 'repo'...
                         _                     _ _ _   
                        | |__   __ _ _ __   __| (_) |_ 
                        | '_ \ / _` | '_ \ / _` | | __|
                        | |_) | (_| | | | | (_| | | |_ 
                        |_.__/ \__,_|_| |_|\__,_|_|\__|
                                                       

                      This is an OverTheWire game server. 
            More information on http://www.overthewire.org/wargames

backend: gibson-1
bandit27-git@bandit.labs.overthewire.org's password: 
remote: Enumerating objects: 3, done.
remote: Counting objects: 100% (3/3), done.
remote: Compressing objects: 100% (2/2), done.
remote: Total 3 (delta 0), reused 0 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (3/3), done.

[~/t] 
$ cd repo

[~/t/repo] 
$ ls
README

[~/t/repo] 
$ cat README 
The password to the next level is: y8Yd2ssKcpHpud7UvOSOxwamRMzIGIeQ
```


<br>






# 28 to 29


```bash
[~/t] 
$ git clone ssh://bandit28-git@bandit.labs.overthewire.org:2220/home/bandit28-git/repo

[~/t] 
$ cd repo/

[~/t/repo] 
$ ls
README.md

[~/t/repo] 
$ cat README.md 
# Bandit Notes
Some notes for level29 of bandit.

## credentials

- username: bandit29
- password: xxxxxxxxxx


[~/t/repo] 
$ git log
commit 83d77407b76c9f86ac4e691a47618641c9d527ba (HEAD -> master, origin/master, origin/HEAD)
Author: Morla Porla <morla@overthewire.org>
Date:   Wed Jun 24 14:59:06 2026 +0000

    fix info leak

commit 13bbc4d2414ffe0439b8ee4f5e5c2949780cf4b3
Author: Morla Porla <morla@overthewire.org>
Date:   Wed Jun 24 14:59:06 2026 +0000

    add missing data

commit f3334fbccbf9446a6af88a3c71021c2f57163322
Author: Ben Dover <noone@overthewire.org>
Date:   Wed Jun 24 14:59:06 2026 +0000

    initial commit of README.md

[~/t/repo] 
$ git show 13bbc4d2414ffe0439b8ee4f5e5c2949780cf4b3
commit 13bbc4d2414ffe0439b8ee4f5e5c2949780cf4b3
Author: Morla Porla <morla@overthewire.org>
Date:   Wed Jun 24 14:59:06 2026 +0000

    add missing data

diff --git a/README.md b/README.md
index 7ba2d2f..42331d9 100644
--- a/README.md
+++ b/README.md
@@ -4,5 +4,5 @@ Some notes for level29 of bandit.
 ## credentials
 
 - username: bandit29
-- password: <TBD>
+- password: Em7eGtqaMySwNFjCpwzzHhLhospOcdt0
```


<br>






# 29 to 30


```bash
[~/t] 
$ git clone ssh://bandit29-git@bandit.labs.overthewire.org:2220/home/bandit29-git/repo

[~/t] 
$ cd repo/

[~/t/repo] 
$ ls
README.md

[~/t/repo] 
$ cat README.md 
# Bandit Notes
Some notes for bandit30 of bandit.

## credentials

- username: bandit30
- password: <no passwords in production!>




[~/t/repo] 
$ git branch -a
* master
  remotes/origin/HEAD -> origin/master
  remotes/origin/dev
  remotes/origin/master
  remotes/origin/sploits-dev

[~/t/repo] 
$ git checkout dev
branch 'dev' set up to track 'origin/dev'.
Switched to a new branch 'dev'

[~/t/repo] 
$ cat README.md 
# Bandit Notes
Some notes for bandit30 of bandit.

## credentials

- username: bandit30
- password: jq9Dfg2rXsfYsWMgFuKlXhphjdH7USgX
```


<br>






# 30 to 31


```bash
[~/t] 
$ git clone ssh://bandit30-git@bandit.labs.overthewire.org:2220/home/bandit30-git/repo

[~/t] 
$ cd repo/

[~/t/repo] 
$ ls
README.md

[~/t/repo] 
$ cat README.md 
just an epmty file... muahaha

[~/t/repo] 
$ git tag
secret

[~/t/repo] 
$ git show secret
82NkymblpGBYmIXG6ZQ8YldBYstHpfUf
```


<br>






# 31 to 32


```bash
[~/t] 
$ git clone ssh://bandit31-git@bandit.labs.overthewire.org:2220/home/bandit31-git/repo

[~/t] 
$ cd repo/

[~/t/repo] 
$ ls
README.md

[~/t/repo] 
$ cat README.md 
This time your task is to push a file to the remote repository.

Details:
    File name: key.txt
    Content: 'May I come in?'
    Branch: master


[~/t/repo] 
$ echo 'May I come in?' > key.txt

[~/t/repo] 
$ git add -f key.txt 

[~/t/repo] 
$ git commit -a -m '.'
[master cd0cc1d] .
 1 file changed, 1 insertion(+)
 create mode 100644 key.txt

[~/t/repo] 
$ git push
remote: ### Attempting to validate files... ####
remote: 
remote: .oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.
remote: 
remote: Well done! Here is the password for the next level:
remote: pWuj5jBQ6IgV0NXwiH6g1pXRF8S1YvbT 
remote: 
remote: .oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.
remote: 
To ssh://bandit.labs.overthewire.org:2220/home/bandit31-git/repo
 ! [remote rejected] master -> master (pre-receive hook declined)
error: failed to push some refs to 'ssh://bandit.labs.overthewire.org:2220/home/bandit31-git/repo'



```


<br>






# 32 to 33


```
WELCOME TO THE UPPERCASE SHELL
>> $0
$ cat /etc/bandit\_pass/bandit33
u4P2CyPOwPGLe94RdD9Uo2FxFwvnFswM
```


<br>







# 33


```
bandit33@bandit:~$ cat README.txt 
Congratulations on solving the last level of this game!

At this moment, there are no more levels to play in this game. However, we are constantly working
on new levels and will most likely expand this game with more levels soon.
Keep an eye out for an announcement on our usual communication channels!
In the meantime, you could play some of our other wargames.

If you have an idea for an awesome new level, please let us know!
```


<br>


