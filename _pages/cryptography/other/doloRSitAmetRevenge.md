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

