---
permalink: /cryptography/other/AESnotes
title: AES notes
---


<br>

<br>


# CBC

```python
from Crypto.Cipher import AES
from os import urandom
from pwn import xor

p1, p2, p3, p4 = b'a'*16, b'b'*16 , b'c'*16, b'd'*16
key = urandom(16)
iv = urandom(16)
p = p1 + p2 + p3 + p4

ct = AES.new(key=key, mode=AES.MODE_CBC, iv=iv).encrypt(p)
c1, c2, c3, c4 = ct[:16], ct[16:32], ct[32:48], ct[48:]

# how does the encryption work?
def ECB_enc(x):
    return AES.new(key, AES.MODE_ECB).encrypt(x)

assert c1 == ECB_enc(xor(p1, iv))
assert c2 == ECB_enc(xor(p2, c1))
assert c3 == ECB_enc(xor(p3, c2))
assert c4 == ECB_enc(xor(p4, c3))
...

# and decryption?
def ECB_dec(x):
    return AES.new(key, AES.MODE_ECB).decrypt(x)

assert p1 == xor(ECB_dec(c1), iv)
assert p2 == xor(ECB_dec(c2), c1)
assert p3 == xor(ECB_dec(c3), c2)
assert p4 == xor(ECB_dec(c4), c3)
...
```
