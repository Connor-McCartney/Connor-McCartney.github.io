---
permalink: /cryptography/other/doloRSitAmetRevenge
title: doloR Sit Amet Revenge
---

<br>

<br>

Challenge:

<https://alpacahack.com/challenges/dolor-sit-amet-revenge>

<br>

```python
#!/usr/local/bin/python

import string
import random
import re
import os
from math import gcd
from Crypto.Util.number import getPrime, bytes_to_long

flag = os.environ.get("FLAG", "BHFlagY{00000000000000000000000000000000}")
assert re.match(r"BHFlagY\{[0-9a-f]{32}}", flag)

def lorem_sentence():
    words = []
    for _ in range(random.randint(16, 20)):
        word = "".join(random.choices(string.ascii_letters, k=random.randint(6, 10)))
        words.append(word)
    return " ".join(words).capitalize() + "."

sentences = []
for i in range(10):
    sentences.append(lorem_sentence())
sentences[0] += f" Congratulations! The flag is {flag}."

e = 13
while True:
    p = getPrime(512)
    q = getPrime(512)
    if gcd((p-1)*(q-1), e) == 1:
        break
n = p * q

print(f"{e = }")
print(f"{n = }")
for sentence in sentences:
    print(re.sub(r"\w", "x", sentence))

for i in range(4):
    seed = int(input(f"#{i+1} seed: "))
    random.seed(seed)
    paragraph = " ".join(random.sample(sentences, k=5))
    pt = bytes_to_long(paragraph.encode())
    ct = pow(pt, e, n)
    print(f"{ct = }")
```


<br>


<br>

---

<br>

Solve:

<br>


```python

Seed 15901 gives [0, 1, 2, 3, 4]  
Seed 17502 gives [1, 2, 3, 4, 0]  

Seed 4145  gives [0, 2, 3, 4, 5]  
Seed 15589 gives [2, 3, 4, 5, 0]
```

The sentences are joined with spaces, we clump together s1, s2, s3, s4 and s2, s3, s4, s5. 

Use resultants to eliminate the clumps. 

Then polygcd/Franklin Reiter to solve s0 (mod n)


<br>

demo:

<br>



```python
import string
import random
import re
import os
from Crypto.Util.number import *

flag = os.environ.get("FLAG", "BHFlagY{00000000000000000000000000000000}")
assert re.match(r"BHFlagY\{[0-9a-f]{32}}", flag)

def lorem_sentence():
    words = []
    for _ in range(random.randint(16, 20)):
        word = "".join(random.choices(string.ascii_letters, k=random.randint(6, 10)))
        words.append(word)
    return " ".join(words).capitalize() + "."

sentences = []
for i in range(10):
    sentences.append(lorem_sentence())
sentences[0] += f" Congratulations! The flag is {flag}."

e = 13
while True:
    p = getPrime(512)
    q = getPrime(512)
    if gcd((p-1)*(q-1), e) == 1:
        break
n = p * q

cts = []
for seed in [15901, 17502, 4145, 15589]:
    random.seed(int(seed))
    paragraph = " ".join(random.sample(sentences, k=5))
    pt = bytes_to_long(paragraph.encode())
    ct = pow(pt, e, n)
    cts.append(ct)

c0, c1, c2, c3 = cts

def resultant(f, g, x):
    # eliminates x
    print('resultant...')
    res = f.sylvester_matrix(g, x).det().univariate_polynomial()
    print('done')
    return res

def polygcd(a, b):
    while b:
        a, b = b, a % b
    return a.monic()

def FranklinReiter(f1, f2):
    return int(-polygcd(f1, f2).coefficients()[0])

def solve_s0_mod_n():
    clump1_len = len(' '.join([sentences[1], sentences[2], sentences[3], sentences[4]]))
    clump2_len = len(' '.join([sentences[2], sentences[3], sentences[4], sentences[5]]))
    s0_len = len(sentences[0])

    PR.<s0, clump1, clump2> = PolynomialRing(Zmod(n))

    p0_ = s0     * 256**(clump1_len+1) + ord(' ') * 256**clump1_len + clump1
    p1_ = clump1 * 256**(s0_len+1)     + ord(' ') * 256**s0_len     + s0
    p2_ = s0     * 256**(clump2_len+1) + ord(' ') * 256**clump2_len + clump2
    p3_ = clump2 * 256**(s0_len+1)     + ord(' ') * 256**s0_len     + s0

    f0 = p0_**e-c0
    f1 = p1_**e-c1
    f2 = p2_**e-c2
    f3 = p3_**e-c3

    return FranklinReiter(resultant(f0, f1, clump1), resultant(f2, f3, clump2))


s0_mod_n = solve_s0_mod_n()
print(f'{s0_mod_n = }')
print(s0_mod_n == bytes_to_long(sentences[0].encode()) % n)
```



<br>


<br>

<br>


Now for part 2. 


Let's treat each character in the first sentence as an unknown and try solve mod n with LLL or BKZ. 

The success rate will heavily depend on the random amount of unknown characters. 

We can make many connections and check before doing anything else to get an easier one with less unknowns. 

```python
import string
import random
import re
import os
from Crypto.Util.number import *

flag = "BHFlagY{00000000000000000000000000000000}"
p = getPrime(512)
q = getPrime(512)
n = p * q

def lorem_sentence():
    words = []
    for _ in range(random.randint(16, 20)):
        word = "".join(random.choices(string.ascii_letters, k=random.randint(6, 10)))
        words.append(word)
    return " ".join(words).capitalize() + "."

sentence0 = lorem_sentence() + f" Congratulations! The flag is {flag}."
prefix = sentence0.split('.')[0]
prefix_num_unknowns = len(prefix) - prefix.count(' ')
print(f'{prefix_num_unknowns = }')
print(sentence0)




unknown_powers = {}
for i in range(2, 34):
    unknown_powers[i] = sentence0[-(1+i)]
for i, c in enumerate(prefix[::-1]):
    unknown_powers[i+len(sentence0.split('.')[1])+2] = c
s0_reconstruction = bytes_to_long(b'}.') + bytes_to_long(b'. Congratulations! The flag is BHFlagY{') * 256**34 + sum([ord(c) * 256**i for i, c in unknown_powers.items()])
print(long_to_bytes(s0_reconstruction).decode() == sentence0)




s0_mod_n = bytes_to_long(sentence0.encode()) % n
t = bytes_to_long(b'}.') + bytes_to_long(b'. Congratulations! The flag is BHFlagY{') * 256**34 - s0_mod_n
assert (t + sum([ord(c) * 256**i for i, c in unknown_powers.items()])) % n == 0
```



