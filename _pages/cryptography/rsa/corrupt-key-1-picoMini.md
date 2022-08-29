---
permalink: /cryptography/rsa/corrupt-key-1-picoMini
title: corrupt-key-1 picoMini
---

<br>

We are given the 256 upper bits of p, which can be solved by bruting some bits and then using coppersmith's method. <br>
The number of bits and m must be tweaked, higher m will take longer but more bits also takes longer...



```python
from tqdm import tqdm

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

    B =  B.LLL()
    f = sum([ZZ(B[0,i]//X**i)*x**i for i in range(B.ncols())])
    roots = set([f.base_ring()(r) for r,m in f.roots() if abs(r) <= X])
    return [root for root in roots if N.gcd(ZZ(f(root))) >= N**beta]

def recover(p_high, n, m):
        p_bits = (len(bin(n))-2)//2
        p_high_bits = len(bin(p_high)) - 2
        PR.<x> = PolynomialRing(Zmod(n))
        f = p_high * 2**(p_bits-p_high_bits) + x
        x = small_roots(f, X=2**(p_bits-p_high_bits), beta=0.4, m=m)
        if x == []:
                return None
        p = int(f(x[0]))
        return p

def solve(bits, m):
    for x in tqdm(range(2**bits)):
        _p = _p_high + x * 2**(256-bits)
        p_high = int(bin(_p)[:256+bits+2], 2)
        p = recover(p_high, n, m)
        if p is not None:
            print(p)

n = 0x00b8cb1cca99b6ac41876c18845732a5cbfc875df346ee9002ce608508b5fcf6b60a5ac7722a2d64ef74e1443a338e70a73e63a303f3ac9adf198595699f6e9f30c009d219c7d98c4ec84203610834029c79567efc08f66b4bc3f564bfb571546a06b7e48fb35bb9ccea9a2cd44349f829242078dfa64d525927bfd55d099c024f
_p_high = 0xe700568ff506bd5892af92592125e06cbe9bd45dfeafe931a333c13463023d4f0000000000000000000000000000000000000000000000000000000000000000
solve(bits=7, m=18)
```









```python
from Crypto.Util.number import *

n = 0x00b8cb1cca99b6ac41876c18845732a5cbfc875df346ee9002ce608508b5fcf6b60a5ac7722a2d64ef74e1443a338e70a73e63a303f3ac9adf198595699f6e9f30c009d219c7d98c4ec84203610834029c79567efc08f66b4bc3f564bfb571546a06b7e48fb35bb9ccea9a2cd44349f829242078dfa64d525927bfd55d099c024f
e = 0x10001
p = 12098520864598198757294135341465388062087431109285224283440314414683283061468500249596026217234382854875647811812632201834942205849073893715844547051090363
q = n//p
d = pow(e, -1, (p-1)*(q-1))
c = open('msg.enc', 'rb').read()
c = bytes_to_long(c)
m = pow(c, d, n)
print(long_to_bytes(m))
#Here is your flag: picoCTF{d741543f172970457e6a9aaa890935b8}
```

