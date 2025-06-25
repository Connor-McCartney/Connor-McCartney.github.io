---
permalink: /cryptography/other/grammarnaziMaltaQuals2025
title: grammar_nazi - Malta Quals 2025
---


<br>

<br>

Challenge: 

<https://github.com/sajjadium/ctf-archives/tree/main/ctfs/MaltaCTF/2025/Quals/crypto/grammar_nazi>

(by Neobeo)

```python
from Crypto.Util.number import *

FLAG = 'maltactf{???????????????????????????????}'
assert len(FLAG) == 41

p = getPrime(128)
q = getPrime(128)
N = p * q
e = 65537

m = f'The flag is {FLAG}'
c = pow(bytes_to_long(m.encode()), e, N)

# ERROR: Sentences should end with a period.
m += '.'
c += pow(bytes_to_long(m.encode()), e, N)

# All good now!
print(f'{N = }')
print(f'{c = }')

'''
N = 83839453754784827797201083929300181050320503279359875805303608931874182224243
c = 32104483815246305654072935180480116143927362174667948848821645940823281560338
'''
```

<br>

<br>

Solve:

Modulus is 256 bits, and neobeo makes an unknown section barely under that:

```python
>>> 8*len('???????????????????????????????')
248
```


```python
from Crypto.Util.number import *

FLAG = 'maltactf{???????????????????????????????}'
assert len(FLAG) == 41
m = f'The flag is {FLAG}'

M = bytes_to_long(m.encode())
t = 256**32 * bytes_to_long(b'The flag is maltactf{') + ord('}')
x = bytes_to_long(b'???????????????????????????????')
assert M == 256*x + t

p = getPrime(128)
q = getPrime(128)
N = p * q
e = 65537

c = pow(bytes_to_long(m.encode()), e, N)
m += '.'
c += pow(bytes_to_long(m.encode()), e, N)

assert c == (pow(M, e, N) + pow(256*M + ord('.'), e, N))
assert c == (pow(256*x + t, e, N) + pow(256*(256*x+t) + ord('.'), e, N))

PR.<X> = PolynomialRing(Zmod(N))
f = (256*X + t)**e + (256*(256*X+t) + ord('.'))**e - c
assert f(X=x) == 0
```

<br>

We obtain 1 equation mod N with 1 unknown... just call .roots() right?

No, with the binomials expanded to exponent 65537 it's too slow....

