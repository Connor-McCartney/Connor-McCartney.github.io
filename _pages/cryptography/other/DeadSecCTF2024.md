---
permalink: /cryptography/other/DeadSecCTF2024
title: DeadSec CTF 2024
---


<br>
<br>

# Password Guesser

```python
from collections import Counter
from Crypto.Util.number import *
from Crypto.Cipher import AES
import hashlib
from Crypto.Util.Padding import pad
import math

flag = b'<REDACTED>'
P = 13**37
password = b'<REDACTED>'
pl = list(password)
pl = sorted(pl)
assert math.prod(pl) % P == sum(pl) % P
password2 = bytes(pl)

print(f"counts = {[cnt for _, cnt in Counter(password2).items()]}")
cipher = AES.new(hashlib.sha256(password2).digest(), AES.MODE_CBC)
print(f"c = {cipher.encrypt(pad(flag, 16))}")
print(f"iv = {cipher.iv}")


'''
counts = [5, 4, 7, 5, 5, 8, 9, 4, 5, 7, 4, 4, 7, 5, 7, 8, 4, 2, 5, 5, 4, 3, 10, 4, 5, 7, 4, 4, 4, 6, 5, 12, 5, 5, 5, 8, 7, 9, 2, 3, 2, 5, 8, 6, 4, 4, 7, 2, 4, 5, 7, 9, 4, 9, 7, 4, 7, 8, 4, 2, 4, 4, 4, 4, 3, 3, 7, 4, 6, 9, 4, 4, 4, 6, 7, 4, 4, 4, 1, 3, 5, 8, 4, 9, 11, 7, 4, 2, 4]
c = b'q[\n\x05\xad\x99\x94\xfb\xc1W9\xcb`\x96\xb9|CA\xb8\xb5\xe0v\x93\xff\x85\xaa\xa7\x86\xeas#c'
iv = b'+\xd5}\xd8\xa7K\x88j\xb5\xf7\x8b\x95)n53'
'''
```

<br>

<br>

$$x_0^{c_0} \cdot x_1^{c_1} \cdot x_2^{c_2} \cdot \ ... \ \equiv x_0 \cdot c_0 + x_1 \cdot c_1 + x_2 \cdot c_2 + \ ... \ \text{  (mod P)}$$

```python
from itertools import combinations
from math import comb, prod
from string import printable
from Crypto.Cipher import AES
import hashlib
from tqdm import tqdm


counts = [5, 4, 7, 5, 5, 8, 9, 4, 5, 7, 4, 4, 7, 5, 7, 8, 4, 2, 5, 5, 4, 3, 10, 4, 5, 7, 4, 4, 4, 6, 5, 12, 5, 5, 5, 8, 7, 9, 2, 3, 2, 5, 8, 6, 4, 4, 7, 2, 4, 5, 7, 9, 4, 9, 7, 4, 7, 8, 4, 2, 4, 4, 4, 4, 3, 3, 7, 4, 6, 9, 4, 4, 4, 6, 7, 4, 4, 4, 1, 3, 5, 8, 4, 9, 11, 7, 4, 2, 4]
c = b'q[\n\x05\xad\x99\x94\xfb\xc1W9\xcb`\x96\xb9|CA\xb8\xb5\xe0v\x93\xff\x85\xaa\xa7\x86\xeas#c'
iv = b'+\xd5}\xd8\xa7K\x88j\xb5\xf7\x8b\x95)n53'


printable = sorted([i for i in printable.encode() if i%13 != 0])
print(len(printable))
print(len(counts))

print(comb(92, 89))

P = 13**37
for perm in tqdm(combinations(printable, r=89)):
    pl = []
    for a,b in zip(counts, perm):
        pl += [b]*a
    if prod(pl) % P == sum(pl) % P:
        #print('win!')
        #print(pl)
        #print(prod(pl) % P, sum(pl))
        cipher = AES.new(hashlib.sha256(bytes(pl)).digest(), AES.MODE_CBC, iv)
        print()
        print(cipher.decrypt(c))
        break
```
