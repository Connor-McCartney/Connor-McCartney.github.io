---
permalink: /cryptography/other/apbq-rsa-ii-DUCTF-2023
title: apbq-rsa-ii - DUCTF 2023
---

<br>
<br>

[Challenge Files](https://github.com/DownUnderCTF/Challenges_2023_Public/tree/main/crypto/apbq-rsa-ii)

```python
from Crypto.Util.number import getPrime, bytes_to_long
from random import randint

p = getPrime(1024)
q = getPrime(1024)
n = p * q
e = 0x10001

hints = []
for _ in range(3):
    a, b = randint(0, 2**312), randint(0, 2**312)
    hints.append(a * p + b * q)

FLAG = open('flag.txt', 'rb').read().strip()
c = pow(bytes_to_long(FLAG), e, n)
print(f'{n = }')
print(f'{c = }')
print(f'{hints = }')
```

<br>

Solve:

We have 3 equations:

$$h_1 = a_1 \ p + b_1 \ q$$

$$h_2 = a_2 \ p + b_2 \ q$$

$$h_3 = a_3 \ p + b_3 \ q$$

Now let's let:

$$x_1 = a_1 \ p, \ \ \ \ x_2 = a_2 \ p, \ \ \ \ x_3 = a_3 \ p$$

