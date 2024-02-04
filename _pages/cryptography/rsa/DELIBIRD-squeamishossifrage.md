---
permalink: /cryptography/rsa/MAGIKARP-squeamishossifrage
title: MAGIKARP - squeamishossifrage
---

<br>

[Challenge](https://github.com/zerosumsecurity/squeamishossifrage/tree/main/MAGIKARP)

<br>

```python
from pwn import remote
from time import time, sleep
from Crypto.Util.number import *

def common_modulus_attack(c1, c2, e1, e2, n):  
   s1 = pow(e1, -1, e2)  
   s2 = int((gcd(e1,e2) - e1 * s1) // e2)  
   temp = pow(c2, -1, n)  
   m1 = pow(c1,s1,n)  
   m2 = pow(temp,-s2,n)  
   return int((m1 * m2) % n)

n = 0xc2e5c046b514624010ea1670b19c497da80f6459bf84c76c45561e55ca97aa379ccf6191db5d8f9c9b66bd5fe288bbadf104c027638f63417256cdc90733e0b618de44c2e7420df47b488cb6ed418cd16541d659fa8e72b0d6086ede5108e5dbee86ac94962ccc3af443a4c5e9aaca61bc3816cbe2b8748e3815c71fca2415d
MODULUS = pow(2,64)
t = int(time())

io = remote("play.squeamishossifrage.eu", "5225")
c1 = int(io.read())
sleep(1)
io = remote("play.squeamishossifrage.eu", "5225")
c2 = int(io.read())


for a in range(10):
    for b in range(10):
        e1 = pow(1337, t+a, MODULUS)
        e2 = pow(1337, t+b, MODULUS)
        try:
            flag = common_modulus_attack(c1, c2, e1, e2, n)
            print(long_to_bytes(flag).decode())
        except:
            pass

# so{d0a1592133ad78522852d6548ae9f866}
```
