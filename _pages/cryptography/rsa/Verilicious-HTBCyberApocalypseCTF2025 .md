---
permalink: /cryptography/rsa/Verilicious-HTBCyberApocalypseCTF2025 
title: Verilicious - HTB Cyber Apocalypse CTF 2025 
---

<br>


Challenge files:

```python
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Util.number import getPrime, long_to_bytes as l2b, bytes_to_long as b2l
from random import seed, randbytes
from data import R, s

seed(s)

class Verilicious:
    def __init__(self):
        self.key = RSA.import_key(open('privkey.pem', 'rb').read())
        self.cipher = PKCS1_v1_5.new(self.key, randbytes)

    def verify(self, c):
        c = b'\x00'*(self.key.n.bit_length()//8-len(c)) + c
        return int(self.cipher.decrypt(c, sen := get_random_bytes(self.key.n.bit_length()//8)) != sen)

    def encrypt(self, m):
        return self.cipher.encrypt(m)

orac = Verilicious()

enc_flag = orac.encrypt(open('flag.txt', 'rb').read()).hex()

assert all(orac.verify(l2b(pow(r, orac.key.e, orac.key.n) * int(enc_flag, 16) % orac.key.n)) for r in R)

import os ; os.system('openssl rsa -in privkey.pem -pubout -out pubkey.pem')

with open('output.txt', 'w') as f:
    f.write(f'{enc_flag = }\n')
    f.write(f'{R = }\n')
```

