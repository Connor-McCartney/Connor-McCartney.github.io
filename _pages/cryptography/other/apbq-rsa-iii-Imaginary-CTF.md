---
permalink: /cryptography/other/apbq-rsa-iii-Imaginary-CTF
title: apbq-rsa-iii - Imaginary CTF
---

<br>
<br>

Challenge:


```python
from Crypto.Util.number import getPrime, bytes_to_long
from random import randint

p = getPrime(1024)
q = getPrime(1024)
n = p * q
e = 0x10001

hints = []
for _ in range(3):
    a, b = randint(0, 3**312), randint(0, 3**312)
    hints.append(a * p + b * q)

FLAG = open('flag.txt', 'rb').read().strip()
c = pow(bytes_to_long(FLAG), e, n)
print(f'{n = }')
print(f'{c = }')
print(f'{hints = }')
```

<br>
