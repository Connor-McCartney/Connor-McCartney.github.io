---
permalink: /cryptography/other/nullcon2025
title: nullcon HackIM CTF Goa 2025
---

<br>


# kleinvieh

```python
from Crypto.PublicKey import RSA

flag = int.from_bytes(open('flag.txt','r').read().strip().encode())
key = RSA.generate(1024)

print(f'n = {key.n}')
print(f'c = {pow(flag, key.e, key.n)}')
phi = (key.p - 1) * (key.q - 1)
print(f'strange = {pow(phi, 2, key.n)}')
```
