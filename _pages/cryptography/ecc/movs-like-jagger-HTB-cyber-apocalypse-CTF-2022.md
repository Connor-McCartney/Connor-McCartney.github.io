---
permalink: /cryptography/ecc/movs-like-jagger-HTB-cyber-apocalypse-CTF-2022 
title: MOVs Like Jagger - HTB Cyber Apocalypse CTF 2022 
---

<br>

[Challenge files](https://github.com/Connor-McCartney/CTF_Files/tree/main/2022/HTB-Cyber-Apocalypse/crypto_movs_like_jagger)


The challenge title hints at the [MOV attack](https://eprint.iacr.org/2018/307.pdf) which works on curves with a small embedding degree. <br>

First we can define our curve and calculate the embedding degree (k):

<br>

```python
a = -35
b = 98
p = 434252269029337012720086440207
Gx = 16378704336066569231287640165
Gy = 377857010369614774097663166640

E = EllipticCurve(GF(p), [a,b])
G = E(Gx, Gy)
A = E(0x53aa256fca975b0e2fd527aac, 0x1d4f956ec8a4458cfda8dff15)
B = E(0x21cd699755718698a1963cd50, 0x21e48edd5538758b156ee9328)

k = 1
while (p**k - 1) % order != 0:
    k += 1
print(k) 
```

We get k=2. Now we transfer the discrete log from $$E(F_p)$$ to $$F_{p^2}^\times$$. 



