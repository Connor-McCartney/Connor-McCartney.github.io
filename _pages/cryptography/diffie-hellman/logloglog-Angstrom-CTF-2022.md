---
permalink: /cryptography/diffie-hellman/logloglog-Angstrom-CTF-2022
title: log log log - Angstrom CTF 2022
---

<br>

[Challenge files](https://github.com/Connor-McCartney/CTF_Files/tree/main/2022/angstromCTF/logloglog)

In this challenge $$p = 2^{1024}q + 1$$,  where q is a very large prime. <br>

We have $$a = g^e\ (mod\ p)$$

The standard Pohlig-Hellman algorithm uses all factors of p-1, but here e is small enough ($$e < 2^{1024}$$) that it can be recovered <br>
without combining the discrete log of every subgroup. (So we don't need to use the factor q, which would take too long as it's a large prime). 


```python
from sympy.ntheory.residue_ntheory import discrete_log #implements the Pohlig–Hellman algorithm
from Crypto.Util.number import long_to_bytes
import numpy as np

g = 3
a = 0xaf99914e5fb222c655367eeae3965f67d8c8b3a0b3c76c56983dd40d5ec45f5bcde78f7a817dce9e49bdbb361e96177f95e5de65a4aa9fd7eafec1142ff2a58cab5a755b23da8aede2d5f77a60eff7fb26aec32a9b6adec4fe4d5e70204897947eb441cc883e4f83141a531026e8a1eb76ee4bff40a8596106306fdd8ffec9d03a9a54eb3905645b12500daeabdb4e44adcfcecc5532348c47c41e9a27b65e71f8bc7cbdabf25cd0f11836696f8137cd98088bd244c56cdc2917efbd1ac9b6664f0518c5e612d4acdb81265652296e4471d894a0bd415b5af74b9b75d358b922f6b088bc5e81d914ae27737b0ef8b6ac2c9ad8998bd02c1ed90200ad6fff4a37
p = 0xb4ec8caf1c16a20c421f4f78f3c10be621bc3f9b2401b1ecd6a6b536c9df70bdbf024d4d4b236cbfcb202b702c511aded6141d98202524709a75a13e02f17f2143cd01f2867ca1c4b9744a59d9e7acd0280deb5c256250fb849d96e1e294ad3cf787a08c782ec52594ef5fcf133cd15488521bfaedf485f37990f5bd95d5796b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001

order = p-1
_g = pow(g, order//(2**1024), p)
_a = pow(a, order//(2**1024), p)

e = discrete_log(_g, _a, p) 

#now flag is just lower bits of e
flag = long_to_bytes(int(np.base_repr(e, 2)[-880:], 2))
print(flag)
#actf{it's log, it's log, it's big, it's heavy, it's wood, it's log, it's log, it's better than bad, it's good}
```
