---
permalink: /cryptography/rsa/corrupt-key-1-picoMini
title: corrupt-key-1 picoMini
---

<br>

We are given 256 upper bits of p, which can be solved by bruting some bits and then using coppersmith's method. <br>
The number of bits and m must be tweaked, higher m will take longer but more bits also takes longer...













```python
from Crypto.Util.number import *

n = 0x00b8cb1cca99b6ac41876c18845732a5cbfc875df346ee9002ce608508b5fcf6b60a5ac7722a2d64ef74e1443a338e70a73e63a303f3ac9adf198595699f6e9f30c009d219c7d98c4ec84203610834029c79567efc08f66b4bc3f564bfb571546a06b7e48fb35bb9ccea9a2cd44349f829242078dfa64d525927bfd55d099c024f
e = 0x10001
p = 12098520864598198757294135341465388062087431109285224283440314414683283061468500249596026217234382854875647811812632201834942205849073893715844547051090363
q = n//p
d = pow(e, -1, (p-1)*(q-1))
c = open('msg.enc', 'rb').read()
c = bytes_to_long(c)
m = pow(c, d, n)
print(long_to_bytes(m))
#Here is your flag: picoCTF{d741543f172970457e6a9aaa890935b8}
```

