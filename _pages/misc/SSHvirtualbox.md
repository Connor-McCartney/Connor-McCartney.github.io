---
permalink: /misc/sshvirtualbox
title: How to SSH into a virtualbox virtual machine
---

<br>


I will be SSHing from my host computer to a kali virtual machine.

In virtualbox network settings, select attached to: NAT and then click port forwarding:

![image](https://raw.githubusercontent.com/Connor-McCartney/Connor-McCartney.github.io/main/_pages/misc/images/networksettings.png)

Add a new entry with guest port 22 and choose a host port:

![image](https://raw.githubusercontent.com/Connor-McCartney/Connor-McCartney.github.io/main/_pages/misc/images/sshentry.png)

Start the SSH service on the virtual machine if there isn't one already:

```
sudo apt install openssh-server
sudo systemctl start ssh
```

Now you're able to SSH into the virtual machine.

```
[connor@fedora ~]$ ssh -p 1234 kali@127.0.0.1  
kali@127.0.0.1's password:    
Linux kali 5.16.0-kali7-amd64 #1 SMP PREEMPT Debian 5.16.18-1kali1 (2022-04-01) x86_64  
  
The programs included with the Kali GNU/Linux system are free software;  
the exact distribution terms for each program are described in the  
individual files in /usr/share/doc/*/copyright.  
  
Kali GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent  
permitted by applicable law.  
 
┌──(kali㉿kali)-[~]  
└─$
```

Next you  might want to setup passwordless login with private/public keys. 

How it works is you create a private/public keypair, then copy your public key to the machine you want to 
login to, then use your private key to authenticate. 

Creating a keypair: (~/.ssh/id_rsa is the private key, ~/.ssh/id_rsa.pub is the public key)

```
[connor@fedora]$ ssh-keygen  
Generating public/private rsa key pair.  
Enter file in which to save the key (/home/connor/.ssh/id_rsa):    
Enter passphrase (empty for no passphrase):    
Enter same passphrase again:    
Your identification has been saved in /home/connor/.ssh/id_rsa  
Your public key has been saved in /home/connor/.ssh/id_rsa.pub  
The key fingerprint is:  
SHA256:2wjgSWDuS8NbHPXr7LPxhFtQwab9uylv97rnlrHSD1E connor@fedora  
The key's randomart image is:  
+---[RSA 3072]----+  
|  o   .  ..      |  
| o . . .  o.     |  
|  . +   .+.     E|  
| o + +  .o.    . |  
|  = = . S  .  .  |  
| . =   + *  .  o |  
|  o     B +  .o +|  
|       ..*. oo.=o|  
|        +o.++o+B=|  
+----[SHA256]-----+
```

Copying the public key to the virtual machine: (it will append it to the file ~/.ssh/authorized_keys)

```
[connor@fedora]$ ssh-copy-id -p 1234 kali@127.0.0.1  
/usr/bin/ssh-copy-id: INFO: Source of key(s) to be installed: "/home/connor/.ssh/id_rsa.pub"  
/usr/bin/ssh-copy-id: INFO: attempting to log in with the new key(s), to filter out any that are already installed  
/usr/bin/ssh-copy-id: INFO: 1 key(s) remain to be installed -- if you are prompted now it is to install the new keys
kali@127.0.0.1's password:    
  
Number of key(s) added: 1
```

Now you can login securely without having to enter your password. 

Note: if you want to use another key not in the default directory (~/.ssh), you can specify it with -i:

```
ssh-copy-id -i key -p 1234 kali@127.0.0.1
ssh -i key -p 1234 kali@127.0.0.1
```

