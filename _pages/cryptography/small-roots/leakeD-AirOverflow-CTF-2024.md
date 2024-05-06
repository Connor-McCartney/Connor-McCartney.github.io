---
permalink: /cryptography/small-roots/leakeD-AirOverflow-CTF-2024
title: leakeD - AirOverflow CTF 2024
---

<br>

# Challenge Files

```
n = 61603353713497481353093789761218837456348814362385572719752742165239826633059364812252664775073080419608503766824937118584276367565405119708719320286638215006454597910054035677680116864260197415814502200955093719693770917690955242561401031837258884926792556374971891937048688925497786201196485657947683940093
e = 65537
c = 55107193277806643465354234996914571876636966411485491161969324994511379928060644450385185733887883775588924346215517683693717173215542747455726024055890520942360605839189499190398912729455982335072850028769962719890485469580480502469912059097824663688877477640889793537652387043555868600302643800484069070010
d_low = 3043961376216184695115588290773915275797924871447606123516914996499688086769
```

<br>

# Testing

I'm just going to guess that phi is (p-1)(q-1) and not lcm(p-1, q-1). 

```python
sage: n.nbits()
1023
sage: d_low.nbits()
251
```

I'll also guess that p and q are 512 bits, and d_low is d % (2**251).

Getting some dummies:

```python
from Crypto.Util.number import *

while True:
    p = ZZ(getPrime(512))
    q = ZZ(getPrime(512))
    n = p*q
    assert p.nbits() == 512
    assert q.nbits() == 512
    e = 65537
    d = pow(e, -1, (p-1)*(q-1))
    d_low = d % (2**251)

    if n.nbits() == 1023 and d_low.nbits() == 251:
        break

print(f"{p = }")
print(f"{q = }")
print(f"{n = }")
print(f"{d = }")
print(f"{d_low = }")
```


Solving p_low (or q_low):

```python
    k = (e*d-1) / ((p-1)*(q-1))
    #print(f"{k = }")

    var('pp')
    f = pp*(1-e*d_low) + k*(n*pp - pp**2 - n + pp) 
    def test():
        for p_low_rec in tqdm(solve_mod(f, 2**251)[::2]):
            p_low_rec = int(p_low_rec[0])
            if p_low_rec == p % 2**251 or p_low_rec == q % 2**251:
                return True
        return False
    print(test())
```


Timing how long to solve with 251 lower bits:

```python
from Crypto.Util.number import *
import time
from subprocess import check_output
from re import findall

def flatter(M):
    z = "[[" + "]\n[".join(" ".join(map(str, row)) for row in M) + "]]"
    ret = check_output(["flatter"], input=z.encode())
    return matrix(M.nrows(), M.ncols(), map(int, findall(b"-?\\d+", ret)))

def small_roots(f, X, beta=1.0, m=None):
    N = f.parent().characteristic()
    delta = f.degree()
    if m is None:
        epsilon = RR(beta^2/f.degree() - log(2*X, N))
        m = max(beta**2/(delta * epsilon), 7*beta/delta).ceil()
    t = int((delta*m*(1/beta - 1)).floor())
    
    f = f.monic().change_ring(ZZ)
    P,(x,) = f.parent().objgens()
    g  = [x**j * N**(m-i) * f**i for i in range(m) for j in range(delta)]
    g.extend([x**i * f**m for i in range(t)]) 
    B = Matrix(ZZ, len(g), delta*m + max(delta,t))

    for i in range(B.nrows()):
        for j in range(g[i].degree()+1):
            B[i,j] = g[i][j]*X**j

    B =  flatter(B)
    f = sum([ZZ(B[0,i]//X**i)*x**i for i in range(B.ncols())])
    roots = set([f.base_ring()(r) for r,m in f.roots() if abs(r) <= X])
    return [root for root in roots if N.gcd(ZZ(f(root))) >= N**beta]


def recover(p_low, n, m, p_bits=512):
    p_low_bits = len(bin(p_low)) - 2
    PR.<x> = PolynomialRing(Zmod(n))
    f = x * 2**p_low_bits + p_low
    x = small_roots(f, X=2**(p_bits-p_low_bits), beta=0.5, m=m)
    if x == []:
        return None
    p = int(f(x[0]))
    if is_prime(p):
        return p
    return None

p = getPrime(512) 
q = getPrime(512)
n = p*q

m = 1
for bits in range(15, -1, -1):
    p_low = int(p % 2**(251 + bits))
    while True:
        starttime = time.time()
        p = recover(p_low, n, m=m)
        t = time.time() - starttime
        if p is not None:
            print(f"bruting {bits} bits with m={m} will take {round(2**bits * t, 2)} seconds (single-threaded)")
            break
        m += 1
```

```
$ sage test.sage
bruting 15 bits with m=16 will take 208295.83 seconds (single-threaded)
bruting 14 bits with m=16 will take 108042.45 seconds (single-threaded)
bruting 13 bits with m=18 will take 92173.73 seconds (single-threaded)
bruting 12 bits with m=29 will take 181708.96 seconds (single-threaded)
bruting 11 bits with m=29 will take 102365.96 seconds (single-threaded)
bruting 10 bits with m=29 will take 47489.22 seconds (single-threaded)
```

It's clear this will take way too long. 

So I searched for another paper (Boneh, D., Durfee, G., Frankel, Y):

<https://www.iacr.org/cryptodb/data/paper.php?pubkey=144>

<https://link.springer.com/content/pdf/10.1007/3-540-49649-1_3.pdf>


<br>


Corollary 1: Given n/4 bits of p_low you can factor n.

It seems they use bivariate instead of univariate??

```python
p = random_prime(2**512)
q = random_prime(2**512)
N = p*q

n = N.nbits()
r = 2**(n//4)
p_low = int(p % r)

```
