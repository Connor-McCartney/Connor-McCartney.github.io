---
permalink: /htb/delivery
title: Delivery
---

<br>

As always, begin with nmap:


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
