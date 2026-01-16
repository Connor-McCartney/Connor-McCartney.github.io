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


suffix_len = len(sentence0.split('.')[1]) + 1
space_powers = [(i + suffix_len + 1) for i, c in enumerate(prefix[::-1]) if c == ' ']
unknown_powers = {}
for i in range(2, 34):
    unknown_powers[i] = sentence0[-(1+i)]
for i, c in enumerate(prefix[::-1]):
    if c != ' ':
        unknown_powers[i+suffix_len+1] = c
assert len(unknown_powers) == prefix_num_unknowns + 32
s0_reconstruction = bytes_to_long(b'}.') + bytes_to_long(b'. Congratulations! The flag is BHFlagY{') * 256**34 + sum([ord(c) * 256**i for i, c in unknown_powers.items()]) + sum([ord(' ') * 256**i for i in space_powers])
print(long_to_bytes(s0_reconstruction).decode() == sentence0)



s0_mod_n = bytes_to_long(sentence0.encode()) % n
t = bytes_to_long(b'}.') + bytes_to_long(b'. Congratulations! The flag is BHFlagY{') * 256**34 + sum([ord(' ') * 256**i for i in space_powers]) - s0_mod_n 
assert (t + sum([ord(c) * 256**i for i, c in unknown_powers.items()])) % n == 0
```




<br>



```python
import string
import random
import re
import os
from Crypto.Util.number import *

flag = "BHFlagY{%s}" % os.urandom(16).hex()
p = getPrime(512)
q = getPrime(512)
n = p * q

def solve(prefix, s0_mod_n):
    suffix_len = len(sentence0.split('.')[1]) + 1
    space_powers = [(i + suffix_len + 1) for i, c in enumerate(prefix[::-1]) if c == ' ']
    unknown_powers = [i for i in range(2, 34)] + [i+suffix_len+1 for i, c in enumerate(prefix[::-1]) if c != ' ']

    t = bytes_to_long(b'}.') + bytes_to_long(b'. Congratulations! The flag is BHFlagY{') * 256**34 + sum([ord(' ') * 256**i for i in space_powers]) - s0_mod_n 


    upper_avg = (ord('Z')+ord('A'))//2
    lower_avg = (ord('z')+ord('a'))//2
    hex_avg = (ord('f')+ord('0'))//2

    for block_size in range(20, 40):

        M = (Matrix([256**i for i in unknown_powers]).stack(diagonal_matrix([1]*(prefix_num_unknowns+32)))
            .augment(vector([t] + [-hex_avg]*32 + [-lower_avg]*(prefix_num_unknowns-1) + [-upper_avg]))
            .augment(vector([n] + [0]* (prefix_num_unknowns+32)))
            .stack(vector([0] + [0] * (prefix_num_unknowns+31) + [1, 0]))
            .T
        )

        NR = 1 # 1 equation
        NV = prefix_num_unknowns + 32 + 1 # num variables
        var_scale = [hex_avg]*32 + [lower_avg]*(prefix_num_unknowns-1) + [upper_avg]
        S = max(var_scale)
        eqS = S << (NR + NV + 1)
        W = diagonal_matrix([eqS] + [S//v for v in var_scale] + [S])

        M = (M*W).dense_matrix()
        print(f'BKZ {block_size = } ...')
        M = M.BKZ(block_size=block_size)#, fp='ld')
        M /= W

        for row in M:
            if row[0] != 0 or abs(row[-1]) != 1:
                continue
            sol = row[1:-1] * row[-1]
            sol += vector([hex_avg]*32 + [lower_avg]*(prefix_num_unknowns-1) + [upper_avg])
            try:
                print(bytes(sol)[::-1])
                break
            except:
                pass

def lorem_sentence():
    words = []
    for _ in range(random.randint(16, 20)):
        word = "".join(random.choices(string.ascii_letters, k=random.randint(6, 10)))
        words.append(word)
    return " ".join(words).capitalize() + "."

connections = 0
while True:
    connections += 1
    sentence0 = lorem_sentence() + f" Congratulations! The flag is {flag}."
    prefix = sentence0.split('.')[0]
    prefix_num_unknowns = len(prefix) - prefix.count(' ')
    if prefix_num_unknowns <= 115: 
        break

print(f'{connections = }')
print(f'{prefix_num_unknowns = }')
print(sentence0)
print(len(sentence0))

s0_mod_n = bytes_to_long(sentence0.encode()) % n
solve(prefix, s0_mod_n)
```




<br>


<br>



Full solver:



```python
from pwn import *
from Crypto.Util.number import *

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

def solve(prefix, s0_mod_n):
    suffix_len = len(sentence0.split('.')[1]) + 1
    space_powers = [(i + suffix_len + 1) for i, c in enumerate(prefix[::-1]) if c == ' ']
    unknown_powers = [i for i in range(2, 34)] + [i+suffix_len+1 for i, c in enumerate(prefix[::-1]) if c != ' ']

    t = bytes_to_long(b'}.') + bytes_to_long(b'. Congratulations! The flag is BHFlagY{') * 256**34 + sum([ord(' ') * 256**i for i in space_powers]) - s0_mod_n 


    upper_avg = (ord('Z')+ord('A'))//2
    lower_avg = (ord('z')+ord('a'))//2
    hex_avg = (ord('f')+ord('0'))//2

    for block_size in range(20, 40):

        M = (Matrix([256**i for i in unknown_powers]).stack(diagonal_matrix([1]*(prefix_num_unknowns+32)))
            .augment(vector([t] + [-hex_avg]*32 + [-lower_avg]*(prefix_num_unknowns-1) + [-upper_avg]))
            .augment(vector([n] + [0]* (prefix_num_unknowns+32)))
            .stack(vector([0] + [0] * (prefix_num_unknowns+31) + [1, 0]))
            .T
        )

        NR = 1 # 1 equation
        NV = prefix_num_unknowns + 32 + 1 # num variables
        var_scale = [hex_avg]*32 + [lower_avg]*(prefix_num_unknowns-1) + [upper_avg]
        S = max(var_scale)
        eqS = S << (NR + NV + 1)
        W = diagonal_matrix([eqS] + [S//v for v in var_scale] + [S])

        M = (M*W).dense_matrix()
        print(f'BKZ {block_size = } ...')
        M = M.BKZ(block_size=block_size)#, fp='ld')
        M /= W

        for row in M:
            if row[0] != 0 or abs(row[-1]) != 1:
                continue
            sol = row[1:-1] * row[-1]
            sol += vector([hex_avg]*32 + [lower_avg]*(prefix_num_unknowns-1) + [upper_avg])
            try:
                print('BHFlagY{%s}' % bytes(sol).decode()[::-1][-32:])
                break
            except:
                pass

while True:
    #io = process(["/home/connor/.p/bin/python", "server.py"]) 
    io = remote('34.170.146.252', 56821)
    io.recvline()
    e = 13
    n = int(io.recvline().decode().split()[-1])

    sentences = []
    sentence0 = io.recvline().decode().strip()

    print(sentence0)
    print(len(sentence0))

    prefix = sentence0.split('.')[0]
    prefix_num_unknowns = len(prefix) - prefix.count(' ')
    print(f'{prefix_num_unknowns = }')
    if prefix_num_unknowns > 116: 
        io.close()
        continue
    print('few unknowns!!!!!!!!!!!!!!!!!!!!')







    sentences.append(sentence0)
    for _ in range(9):
        sentences.append(io.recvline().decode().strip())

    print(io.recv())
    io.sendline(b'15901')
    c0 = int(io.recvline().decode().split()[-1])

    io.recv()
    io.sendline(b'17502')
    c1 = int(io.recvline().decode().split()[-1])

    io.recv()
    io.sendline(b'4145')
    c2 = int(io.recvline().decode().split()[-1])

    io.recv()
    io.sendline(b'15589')
    c3 = int(io.recvline().decode().split()[-1])

    s0_mod_n = solve_s0_mod_n()
    solve(prefix, s0_mod_n)
    break

```


<br>

```
[+] Opening connection to 34.170.146.252 on port 56821: Done
INFO:pwnlib.tubes.remote.remote.140667801856336:Opening connection to 34.170.146.252 on port 56821: Done
xxxxxxxx xxxxxxx xxxxxxxxxx xxxxxx xxxxxx xxxxxx xxxxxxxxx xxxxxxx xxxxxxx xxxxxxxx xxxxxx xxxxxxx xxxxxx xxxxxx xxxxxx xxxxxxxxx. xxxxxxxxxxxxxxx! xxx xxxx xx xxxxxxx{xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}.
202
prefix_num_unknowns = 114
few unknowns!!!!!!!!!!!!!!!!!!!!
b'#1 seed: '
resultant...
done
resultant...
done
BKZ block_size = 20 ...
BKZ block_size = 21 ...
BHFlagY{44164157d5fe70a6a5211c13fcfc6a9f}
```



<br>

First blood xD


<img width="520" height="109" alt="image" src="https://github.com/user-attachments/assets/71d5f550-028e-49c6-8ab8-1c805750e174" />
