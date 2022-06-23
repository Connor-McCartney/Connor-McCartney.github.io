---
permalink: /cryptography/small-roots/delta-CrewCTF-2022
title: delta - CrewCTF 2022
---

<br>

[Challenge files](https://github.com/Connor-McCartney/CTF_Files/tree/main/2022/CrewCTF/delta)

<br>

```python
delta = getRandomNBitInteger(64)
x = p**2 + 1337*p + delta

val = (pow(2,e,n)*(x**3) + pow(3,e,n)*(x**2) + pow(5,e,n)*x + pow(7,e,n)) % n
```

<br>

small_roots will find x mod p. Note that $$x = p^2 + 1337p + delta$$ so $$x \ (mod \ p) = delta$$. <br>

delta is a 64 bit integer so our bound should be $$2^{64}$$. We also know p < q, so p < $$n^{0.5}$$, so beta should be 0.5

```python
PR.<x> = PolynomialRing(Zmod(n))
f = pow(2,e,n)*(x**3) + pow(3,e,n)*(x**2) + pow(5,e,n)*x + pow(7,e,n) - val
delta = small_roots(f, X=2^64, beta=0.5)[0]
```

Next, x = delta mod p, so fn(x) = fn(delta) = 0 mod p, so p divides fn(delta)

Therefore p can be recovered with gcd!

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Util.number import long_to_bytes, inverse

def small_roots(f, X, beta=1.0):
    N = f.parent().characteristic()
    delta = f.degree()
    epsilon = RR(beta^2/f.degree() - log(2*X, N))
    f = f.monic().change_ring(ZZ)
    P,(x,) = f.parent().objgens()
    m = max(beta**2/(delta * epsilon), 7*beta/delta).ceil()
    t = int((delta*m*(1/beta - 1)).floor())
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


n = 141100651008173851466795684636324450409238358207191893767666902216680426313633075955718286598033724188672134934209410772467615432454991738608692590241240654619365943145665145916032591750673763981269787196318669195238077058469850912415480579793270889088523790675069338510272116812307715222344411968301691946663
e = 65537
c = 115338511096061035992329313881822354869992148130629298132719900320552359391836743522134946102137278033487970965960461840661238010620813848214266530927446505441293867364660302604331637965426760460831021145457230401267539479461666597608930411947331682395413228540621732951917884251567852835625413715394414182100
val = 55719322748654060909881801139095138877488925481861026479419112168355471570782990525463281061887475459280827193232049926790759656662867804019857629447612576114575389970078881483945542193937293462467848252776917878957280026606366201486237691429546733291217905881521367369936019292373732925986239707922361248585

PR.<x> = PolynomialRing(Zmod(n))
f = pow(2,e,n)*(x**3) + pow(3,e,n)*(x**2) + pow(5,e,n)*x + pow(7,e,n) - val
delta = small_roots(f, X=2^64, beta=0.5)[0]

p = gcd(int(f(delta)), n)
q = n//p
assert p*q == n

d = inverse(e, (p-1)*(q-1))
key = RSA.construct((int(n), int(e), int(d), int(p), int(q)))
flag = PKCS1_OAEP.new(key=key, hashAlgo=SHA256).decrypt(long_to_bytes(c))
print(flag)
#crew{m0dp_3qu4710n_l34d5_u5_f4c70r1n6}
```
