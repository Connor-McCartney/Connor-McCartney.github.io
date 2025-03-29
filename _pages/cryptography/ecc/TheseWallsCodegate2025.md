---
permalink: /cryptography/ecc/TheseWallsCodegate2025
title: These Walls - Codegate 2025
---

<br>

<br>

[Challenge Files](https://github.com/Connor-McCartney/CTF_Files/tree/main/2025/codegate/These_Walls)


<br>

```python
from secret import P, s, o, wrong, flag
from Crypto.Cipher import AES
import random, os, math

assert P * o == P.curve()(0)
assert all(math.gcd(o, w) == 1 for w in wrong + [s])
assert all(P * s != P * w for w in wrong)

key = os.urandom(32)
enc_flag = AES.new(key, AES.MODE_CTR, nonce=bytes(12)).encrypt(flag.encode())

print(f"{enc_flag.hex() = }\n{o = }")

key = int.from_bytes(key)
for i in range(32 * 8):
	P *= [random.choice(wrong), s][(key >> i) & 1]
	print(P.xy())
```

<br>

<br>

<br>

# Solve:

Author's writeup: <https://github.com/soon-haari/my-ctf-challenges/tree/main/2025-codegate/crypto-thesewalls>

<br>

There are many steps to break down. 

# 1. Getting curve parameters

You can do something like this: <https://hackropole.fr/en/writeups/fcsc2021-crypto-lost-curve/984a2038-3039-42c2-af1b-8d671c8d5cb0/>


