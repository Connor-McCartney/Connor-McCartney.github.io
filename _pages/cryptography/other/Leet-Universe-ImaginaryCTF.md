```
permalink: /cryptography/other/Leet-Universe-ImaginaryCTF
title: Leet Universe - Imaginary CTF
```

Challenge:

```python
from math import gcd
import os

flag = os.environ.get(
    "FLAG", "jctf{red_flags_and_fake_flags_form_an_equivalence_class}"
)

x = int(input("x = "))
g = gcd(x**13 + 37, (x + 42) ** 13 + 42)
print(flag[:g])
```

Solve:

```python
from pwn import remote

def polygcd(a, b):
    while b:
        a, b = b, a % b
    return a.monic()

def solve(f):
    return f.change_ring(ZZ).roots()[0][0]

io = remote("ictf.maple3142.net", "7331")
P.<x> = ZZ[]
f = x**13 + 37
g = (x + 42)**13 + 42
modulus = f.resultant(g)

P.<x> = PolynomialRing(Zmod(modulus))
x = solve(polygcd(P(f), P(g))) # % modulus
io.sendline(str(x).encode())
print(io.readline().decode())
#ictf{the_answer_to_the_1337th_universe_is_15682...36957}
```
