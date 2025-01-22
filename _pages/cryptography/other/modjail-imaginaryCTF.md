---
permalink: /cryptography/other/modjail-imaginaryCTF
title: modjail - imaginary CTF
---

<br>
<br>


Challenge:

```python
#!/usr/bin/python3
from Crypto.Util.number import getPrime, long_to_bytes
from secret import flag
from secrets import randbelow

p = getPrime(1024)
r = randbelow(p)
print(f'{r} mod {p}')
n = int(input())
if n%p != r:
    print('no')
    exit()
print(eval(long_to_bytes(n)))
```

<br>

Solve:

My idea is send `flag# ...<random bytes>` (except null '\x00')

`M * 256**j + x ≡ r (mod p)`
