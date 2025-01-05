---
permalink: /cryptography/other/Not-so-hard-RSA-HITCON-2019-Quals
title: Not so hard RSA - HITCON 2019 Quals
---


<br>
<br>

Challenge:

<br>

```python
from Crypto.Util.number import *
from os import urandom
from SECRET import d


T = 10
def encrypt(data):
    num = bytes_to_long(data)
    p = getPrime(512)
    q = getPrime(512)
    n = p*q
    assert num < n
    phi = (p-1)*(q-1)
    e = inverse(d,phi)
    a = pow(num,e,n)
    enc = long_to_bytes(a).hex()
    return (n,e,enc)

flag = b'redacted'
print(d.bit_length())
for _ in range(T):
    data = flag + urandom(40)
    print(encrypt(data))
```

<br>

<br>

Solve:
