---
permalink: /cryptography/diffie-hellman/Rookie-Mistake-HTB
title: Rookie Mistake - HTB
---

<br>

```python
import os
from Crypto.Util.number import bytes_to_long, getPrime
from sympy import *
from secret import flag

flag1 = bytes_to_long(flag[:len(flag)//2] + os.urandom(69))
flag2 = bytes_to_long(flag[len(flag)//2:] + os.urandom(200))

def genprime():
    p = 2
    while p.bit_length() < 1020:
        p *= getPrime(30)
    while True:
        x = getPrime(16)
        if isprime((p * x) + 1):
            return (p * x) + 1
            break
      
p,q = [genprime() for _ in range(2)]

print("-" * 10 + "RSA PART" + "-" * 10)

e = 0x69420
ct1 = pow(flag1,e,p)

print(f'p: {hex(p)}')
print(f'e: {hex(e)}')
print(f'ct: {hex(ct1)}')

print("-" * 10 + "DH PART" + "-" * 10)

n = p * q
g = 0x69420
ct2 = pow(g, flag2, n)

print(f'n: {hex(n)}')
print(f'g: {hex(g)}')
print(f'ct: {hex(ct2)}')

"""
----------RSA PART----------
p: 0x16498bf7cc48a7465416e0f9ec8034f4030991e73aff9524ef74cc574228e36e6e1944c7686f69f0d1186a69b7aa77d7e954edc8a6932f006786f4648ecc8d4f4d3f6c03d9a1ee9fe61b28b6dd2791a63be581b8811a8ac90a387241ea68b7d36b4a274f64c7a721ad55cfcef23cd14c72542f576e4b507c11c4fa198e80021d484691b
e: 0x69420
ct: 0xa82b37d57b6476fa98f6ee7c278d934bd96c49aa1c5399552d25211230d76cb16ade049572bf631e3849903638d41c884957b9592d0aa072b2bdc3105fe0e3253284f85286ec613966f9cde77ae06e2053dc2254e44ca673b4c76879eff84e5fc32af976c1bfafe147a277d72aad674db749ed8f34d2ebe8189cf12afc9baa17764e4b
----------DH PART----------
n: 0xbe30ccaf896c16f53515e298df25df9158d0a95295c119f0444398b94fae26c0b4cf3a43b120cf0fb657069e0621eb1d2dd832eef3065e80ddbc35854dd4585cc41fd6a5b36339c0d9fcc066272be6818be6a624f75482bbb9c408010ac8c27b20397d870bfcb14e6318097b1601f99e391c9b68c5c586f8da561ff8507be9212713b910b748370ce692c11afa09b74ce80c5f5dd72046415aeed85e1ecedca14abe17ed19ab97729b859120699d9f80dd13f8483773df15b938b8399702a6e846b8728a70f1940d4c6e5835a06a89925eb1ec91a796f270e2d9be1a2c4bee5517109c161f04333d9c0d4034fbbd2dcf69fe734b759a89937f4d8ea0ee6b8385aae14a2cce361
g: 0x69420
ct: 0x65d57a564b8a8667a956705442063392b9b975b8ef869a6dbed04d6e585351f559fe6f5d96823f60b7306740fe2cf5aa81e4a12736d4f0a4826cbc8b4312643af19c75432b4ab222837031851f312df5d707b39bdf2d272f25c1947f3e2943f3592cb0519fee8f4b458021b6b8ee4eabeeae5127d412df4f6a88f66d7cc34c6bb77e0a1440737d0e167f9489f0c7fbfd7f6a5870b4b2865d29b91f6c2b375951e85b1b9f03887d4d3c4a6218111a95021ed1d554c57269e7830c3e7b8e17d13e1fb75ee9f305833d0cb6bfab738572cdbbc8b33b878ad25f78d47d7f449a6c348f5f9f1df3e09f924534a3669b4e69bd0411d154ec756b210691e2efc4a55aa664d938a868f4d
"""
```


Part 1:

$$
c \equiv m^e \ (mod \ p) 
$$

$$
m = c^{(e^{-1} \ (mod \ p-1))} \ (mod\ p)
$$

We have a problem however: e is not invertible mod p-1.

GCD(e, p-1) = 2

We take inverse of e/2 mod p-1, but this still is not working.

Then I tried inverse of e/2 mod (p-1)/2 and this finally works. 

Then we must take the modular square root. 

<br>
<br>

Part 2:

Unlike [https://connor-mccartney.github.io/cryptography/diffie-hellman/nsa-backdoorpicoCTF-2022](https://connor-mccartney.github.io/cryptography/diffie-hellman/nsa-backdoorpicoCTF-2022) m>p and m>q.

First calculate order:

```python
from sympy.ntheory.factor_ import factorint
from sympy.core.numbers import igcd
from sympy.utilities.misc import as_int


def n_order(a, n, f):
    """Returns the order of ``a`` modulo ``n``.
    The order of ``a`` modulo ``n`` is the smallest integer
    ``k`` such that ``a**k`` leaves a remainder of 1 with ``n``.
    Examples
    ========
    >>> from sympy.ntheory import n_order
    >>> n_order(3, 7)
    6
    >>> n_order(4, 7)
    3
    """
    from collections import defaultdict
    a, n = as_int(a), as_int(n)
    if igcd(a, n) != 1:
        raise ValueError("The two numbers should be relatively prime")
    factors = defaultdict(int)
    for px, kx in f.items():
        if kx > 1:
            factors[px] += kx - 1
        fpx = factorint(px - 1)
        for py, ky in fpx.items():
            factors[py] += ky
    group_order = 1
    for px, kx in factors.items():
        group_order *= px**kx
    order = 1
    if a > n:
        a = a % n
    for p, e in factors.items():
        exponent = group_order
        for f in range(e + 1):
            if pow(a, exponent, n) != 1:
                order *= p ** (e - f + 1)
                break
            exponent = exponent // p
    return order


n = 0xbe30ccaf896c16f53515e298df25df9158d0a95295c119f0444398b94fae26c0b4cf3a43b120cf0fb657069e0621eb1d2dd832eef3065e80ddbc35854dd4585cc41fd6a5b36339c0d9fcc066272be6818be6a624f75482bbb9c408010ac8c27b20397d870bfcb14e6318097b1601f99e391c9b68c5c586f8da561ff8507be9212713b910b748370ce692c11afa09b74ce80c5f5dd72046415aeed85e1ecedca14abe17ed19ab97729b859120699d9f80dd13f8483773df15b938b8399702a6e846b8728a70f1940d4c6e5835a06a89925eb1ec91a796f270e2d9be1a2c4bee5517109c161f04333d9c0d4034fbbd2dcf69fe734b759a89937f4d8ea0ee6b8385aae14a2cce361
p = 0x16498bf7cc48a7465416e0f9ec8034f4030991e73aff9524ef74cc574228e36e6e1944c7686f69f0d1186a69b7aa77d7e954edc8a6932f006786f4648ecc8d4f4d3f6c03d9a1ee9fe61b28b6dd2791a63be581b8811a8ac90a387241ea68b7d36b4a274f64c7a721ad55cfcef23cd14c72542f576e4b507c11c4fa198e80021d484691b
q = n // p
g = 0x69420

order = n_order(g, n, {p: 1, q: 1})
assert order == (p-1)*(q-1) // 2
```


```python
from sympy.ntheory.residue_ntheory import _discrete_log_pohlig_hellman
from sympy.ntheory.residue_ntheory import sqrt_mod
from Crypto.Util.number import long_to_bytes
from math import gcd

# part 1
c = 0xa82b37d57b6476fa98f6ee7c278d934bd96c49aa1c5399552d25211230d76cb16ade049572bf631e3849903638d41c884957b9592d0aa072b2bdc3105fe0e3253284f85286ec613966f9cde77ae06e2053dc2254e44ca673b4c76879eff84e5fc32af976c1bfafe147a277d72aad674db749ed8f34d2ebe8189cf12afc9baa17764e4b
p = 0x16498bf7cc48a7465416e0f9ec8034f4030991e73aff9524ef74cc574228e36e6e1944c7686f69f0d1186a69b7aa77d7e954edc8a6932f006786f4648ecc8d4f4d3f6c03d9a1ee9fe61b28b6dd2791a63be581b8811a8ac90a387241ea68b7d36b4a274f64c7a721ad55cfcef23cd14c72542f576e4b507c11c4fa198e80021d484691b
e = 0x69420

m = pow(c, pow(e//2, -1, (p-1)//2), p)
m = sqrt_mod(m, p)
part1 = long_to_bytes(m)[:52]

# part 2
n = 0xbe30ccaf896c16f53515e298df25df9158d0a95295c119f0444398b94fae26c0b4cf3a43b120cf0fb657069e0621eb1d2dd832eef3065e80ddbc35854dd4585cc41fd6a5b36339c0d9fcc066272be6818be6a624f75482bbb9c408010ac8c27b20397d870bfcb14e6318097b1601f99e391c9b68c5c586f8da561ff8507be9212713b910b748370ce692c11afa09b74ce80c5f5dd72046415aeed85e1ecedca14abe17ed19ab97729b859120699d9f80dd13f8483773df15b938b8399702a6e846b8728a70f1940d4c6e5835a06a89925eb1ec91a796f270e2d9be1a2c4bee5517109c161f04333d9c0d4034fbbd2dcf69fe734b759a89937f4d8ea0ee6b8385aae14a2cce361
g = 0x69420
c = 0x65d57a564b8a8667a956705442063392b9b975b8ef869a6dbed04d6e585351f559fe6f5d96823f60b7306740fe2cf5aa81e4a12736d4f0a4826cbc8b4312643af19c75432b4ab222837031851f312df5d707b39bdf2d272f25c1947f3e2943f3592cb0519fee8f4b458021b6b8ee4eabeeae5127d412df4f6a88f66d7cc34c6bb77e0a1440737d0e167f9489f0c7fbfd7f6a5870b4b2865d29b91f6c2b375951e85b1b9f03887d4d3c4a6218111a95021ed1d554c57269e7830c3e7b8e17d13e1fb75ee9f305833d0cb6bfab738572cdbbc8b33b878ad25f78d47d7f449a6c348f5f9f1df3e09f924534a3669b4e69bd0411d154ec756b210691e2efc4a55aa664d938a868f4d
q = n//p

order = (p-1)*(q-1)//gcd(p-1, q-1)
m = _discrete_log_pohlig_hellman(n, c, g, order)
part2 = long_to_bytes(m)[:52]

print(part1 + part2)
```
