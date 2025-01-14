---
permalink: /cryptography/rsa/SUrsa-SUCTF2025
title: SU_rsa - SUCTF 2025
---

<br>

Challenge:

<br>

```python
from Crypto.Util.number import *
from hashlib import sha256
flag = open("flag.txt").read()
p = getPrime(512)
q = getPrime(512)
e = getPrime(256)
n = p*q
d = inverse(e,(p-1)*(q-1))
d_m = ((d >> 512) << 512)
print("d_m = ",d_m)
print("n = ",n)
print("e = ",e)

assert flag[6:-1] == sha256(str(p).encode()).hexdigest()[:32]
# d_m =  54846367460362174332079522877510670032871200032162046677317492493462931044216323394426650814743565762481796045534803612751698364585822047676578654787832771646295054609274740117061370718708622855577527177104905114099420613343527343145928755498638387667064228376160623881856439218281811203793522182599504560128
# n =  102371500687797342407596664857291734254917985018214775746292433509077140372871717687125679767929573899320192533126974567980143105445007878861163511159294802350697707435107548927953839625147773016776671583898492755338444338394630801056367836711191009369960379855825277626760709076218114602209903833128735441623
# e =  112238903025225752449505695131644979150784442753977451850362059850426421356123
```

<br>

Solve:

e is large and we're given the MSB of d. 


First we can solve for p mod e

```python
from Crypto.Util.number import *

p = getPrime(512)
q = getPrime(512)
e = getPrime(256)
n = p*q
d = inverse(e,(p-1)*(q-1))
d_m = ((d >> 512) << 512)

k = (d_m*e-1)//n + 1
PR.<x> = PolynomialRing(GF(e))
f = 1 + k*(n+1-x)
S = f.roots()[0][0] # p+q mod e
PR.<x> = PolynomialRing(GF(e))
f = x^2 - S*x + n
possible_p_mod_e = [i for i, _ in f.roots()]
assert p%e in possible_p_mod_e
```

<br>

<br>

Then we introduce a new variable t to solve for 

```python
from Crypto.Util.number import *

while True:
    p = getPrime(512)
    q = getPrime(512)
    e = getPrime(256)
    n = p*q
    d = inverse(e,(p-1)*(q-1))
    d_m = ((d >> 512) << 512)

    p_mod_e = int(p % e)
    t = int(p - p_mod_e)//e 
    assert p == e*t + p_mod_e
    print(t.bit_length())
    assert t < 2**257
```

<br>

The coppersmith bound is tight, p is 512 bits and we have 257 unknown bits.

Let's bruteforce part of t, I'll choose the LSB.

<br>

```python
from Crypto.Util.number import *

while True:
    p = getPrime(512)
    q = getPrime(512)
    e = getPrime(256)
    n = p*q
    d = inverse(e,(p-1)*(q-1))
    d_m = ((d >> 512) << 512)

    p_mod_e = int(p % e)
    p_mod_e = int(p % e)
    t = int(p - p_mod_e)//e 
    assert p == e*t + p_mod_e
    assert t < 2**257

    BRUTE = 10 # adjustable
    t_low = int(t % 2**BRUTE)
    t_high = (t - t_low) >> BRUTE
    assert t == t_high * 2**BRUTE + t_low

    PR.<x> = PolynomialRing(Zmod(n))
    f = e*(x*2**BRUTE + t_low) + p_mod_e
    assert int(f(x=t_high)) % p == 0
```