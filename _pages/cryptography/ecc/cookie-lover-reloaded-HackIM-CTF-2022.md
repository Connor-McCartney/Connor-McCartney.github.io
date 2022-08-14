---
permalink: /cryptography/ecc/cookie-lover-reloaded-HackIM-CTF-2022
title: cookie lover reloaded - HackIM CTF 2022
---

<br>

[Challenge files](https://github.com/Connor-McCartney/CTF_Files/tree/main/2022/HackIM/cookie_lover_reloaded)


Wikipedia gives a good explanation of [ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm)

This challenge gives you signatures, but this is the vulnerable line:

```python
k = int(hashlib.md5(os.urandom(16)).hexdigest()[:4], 16)
```

k must usually be kept secret, but now it is easily bruteforceable (k < 65536)

Then calculate possible privkey for each k as:

$$a = \frac{sk-z}{r}$$

```python
import hashlib
from tqdm import tqdm
from pwn import *

p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a = -3
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
E = EllipticCurve(GF(p), [a, b])
n = E.order()
G = E(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)

msg = b"random message"
z = int(hashlib.md5(msg).hexdigest(),16)

# get pubkey
io = remote("52.59.124.14", 10005)
io.readuntil(b"Point(")
Ax, Ay = io.readline().decode()[:-2].split(",")
A = E(int(Ax), int(Ay))

# sign 'random message'
io.readuntil(b"signature to check]")
io.sendline(b"1:random message")
io.readline()
io.readline()
r, s = io.readline().decode()[1:-2].split(",")
r, s = int(r), int(s)

for k in tqdm(range(65536)):
    a = (((s*k - z) * pow(r, -1, n)) % n)
    if G * a == A:
        x,y = (G*k).xy() #can sign with any k
        x,y = int(x),int(y)
        r = x % n
        s = pow(k, -1, n) * (int(hashlib.md5(b'I still love cookies.').hexdigest(),16) + r * a) % n

        io.readuntil(b"signature to check]")
        io.sendline(b"2:%d,%d" % (r,s))
        io.readline()
        io.readline()
        print(io.readline().decode())
        break

#ENO{gr33tings_fr0m_the_PS3}
```
