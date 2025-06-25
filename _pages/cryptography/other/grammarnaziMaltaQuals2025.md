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


