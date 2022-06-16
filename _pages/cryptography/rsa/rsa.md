---
permalink: /cryptography/rsa
title: RSA
---

<br>





### Key Recovery - San Diego CTF 2022

__vulnerability: partial private key___

[Writeup](/cryptography/rsa/key-recovery-SDCTF-2022)














# [Can't Login - Incognito CTF 2022](https://github.com/Connor-McCartney/CTF_Files/tree/main/2022/ICTF)

__vulnerability: common ssh-key password__


In the [youtube link](https://www.youtube.com/watch?v=85q6kX5dSoY), there is a ssh key. <br>
Using image to text tools online I recreated the id_rsa file. <br>
I've uploaded it [here](https://github.com/Connor-McCartney/CTF_Files/blob/main/2022/ICTF/id_rsa). <br>
Next create a hashfile using: <br>

```
python ssh2john.py id_rsa > hash
```

Now I tried cracking with johntheripper. But I got error <br>
"SSH cipher value of 6 is not supported!" <br>
Turns out I needed the absolute latest version of john. <br>
So I followed instructions to build from source and cracked it using rockyou.txt after 15 minutes, <br>
giving ictf{drummerboy}.

![image](https://raw.githubusercontent.com/Connor-McCartney/Connor-McCartney.github.io/main/_pages/cryptography/rsa/images/john.png)
