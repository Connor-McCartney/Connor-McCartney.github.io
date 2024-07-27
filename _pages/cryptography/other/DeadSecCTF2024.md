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


# Password Guesser Revenge

```python
from collections import Counter
from Crypto.Util.number import *
from Crypto.Cipher import AES
import hashlib
from Crypto.Util.Padding import pad
import math

flag = b'<redacted>'
P = 13**37
password = b'<redacted>' # password charset is string.printable
pl = list(password)
pl = sorted(pl)
assert math.prod(pl) % P == sum(pl) % P
password2 = bytes(pl)
#print(password2)
print(f"counts = {[cnt for _, cnt in Counter(password).items()]}")
cipher = AES.new(hashlib.sha256(password2).digest(), AES.MODE_CBC)
print(f"c = {cipher.encrypt(pad(flag, 16))}")
print(f"iv = {cipher.iv}")


'''
counts = [2, 4, 14, 7, 3, 2, 5, 3, 1, 3, 1, 4, 3, 3, 2, 10, 2, 6, 4, 1, 3, 4, 3, 2, 4, 3, 6, 1, 1, 4, 2, 21, 8, 8, 2, 4, 1, 9, 3, 4, 8, 3, 1, 2, 2, 5, 8, 2, 7, 2, 9, 2, 2, 6, 6, 3, 3, 9, 1, 3, 6, 6, 2, 4, 5, 3, 3, 8, 5, 1, 1, 9, 2, 8, 4, 1, 4, 9, 4, 1, 3, 4, 3, 4, 6, 4]
c = b'\xfb\x9e\xda\x81\xa6\xdf.\xc9zw\xb6t\x9e\x05\xb7\xdb\x84\xe5\x01\x97\xfb\xd2\x04 i\xa5\x13d\xfd\x89c\x0b'
iv = b'\xd4\xa6\xbc\xae\t/\xd3\x85YY\xb5\xda\xcf\xcaX\xb3'
'''
```

<br>

The difference in this one is the counts of the unsorted password is given. 
