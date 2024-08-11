---
permalink: /cryptography/other/LIT-CTF-2024
title: LIT CTF 2024
---


<br>

# simple otp

just xor with the given key, easy peasy

```python
import random
from pwn import xor
encoded_with_xor = b'\x81Nx\x9b\xea)\xe4\x11\xc5 e\xbb\xcdR\xb7\x8f:\xf8\x8bJ\x15\x0e.n\\-/4\x91\xdcN\x8a'
random.seed(0)
key = random.randbytes(32)
print(xor(encoded_with_xor, key))
# LITCTF{sillyOTPlol!!!!sdfsgvkhf}
```

<br>

# privatekey
