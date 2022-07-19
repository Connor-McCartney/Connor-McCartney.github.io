---
permalink: /cryptography/rsa/Lorge-Imaginary-CTF-2022
title: Lorge - Imaginary CTF 2022
---

<br>

[Challenge Files](https://github.com/Connor-McCartney/CTF_Files/tree/main/2022/ImaginaryCTF/Lorge)

This challenge identifies a case in which regular Pollard p-1 factorisation does not work. 

(largest prime factor of p-1 and q-1 is the same)

Once we identify this largest prime factor (19071329), we can retry using g=pow(2,19071329,n)

```python
from gmpy2 import gcd, powmod, next_prime
from Crypto.Util.number import long_to_bytes

n=63038895359658613740840475285214364620931775593017844102959979092033246293689886425959090682918827974981982265129797739561818809641574878138225207990868931316825055004052189441093747106855659893695637218915533940578672431813317992655224496134300271524374912502175195904393797412770270676558054466831561609036199966477
e=65537
ct=60515029337308681079476677877525631415600527185785323978384495461916047877351538207473264679842349366162035496831534576192102896080638477601954951097077261305183669746007206897469286005836283690807247174941785091487066018014838515240575628587875110061769222088950451112650700101446260617299040589650363814995825303369

def pollard_factorisation(N, g=2):
        k=2
        while True:
                g = powmod(g, k, N)
                p = gcd(g-1,N)
                if p != 1 and p != N:
                        return p, N//p
                if g == 1:
                        print("Failed - (largest prime factor of p-1 and q-1 is the same) -", k)
                        return None
                k = next_prime(k)

pollard_factorisation(n)

p, q = pollard_factorisation(n, g=pow(2,19071329,n))
d = pow(e, -1, (p-1)*(q-1))
flag = long_to_bytes(pow(ct, d, n))
print(flag.decode())
```
