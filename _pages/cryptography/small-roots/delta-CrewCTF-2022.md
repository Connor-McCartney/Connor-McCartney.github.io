---
permalink: /cryptography/small-roots/delta-CrewCTF-2022
title: delta - CrewCTF 2022
---

<br>

[Challenge files](https://github.com/Connor-McCartney/CTF_Files/tree/main/2022/CrewCTF/delta)

```python
delta = getRandomNBitInteger(64)
x = p**2 + 1337*p + delta

val = (pow(2,e,n)*(x**3) + pow(3,e,n)*(x**2) + pow(5,e,n)*x + pow(7,e,n)) % n
```

<br> 

We need to choose parameters for small_roots: <br>
X – the bound for the root <br>
beta – compute a root mod b where b is a factor of N and $$b \geq N^β$$ (Default: 1.0, so b=N) <br>

It is unclear if small_roots will compute a root mod p or a root mod q. <br>
We know that $$p < n^{0.5} < q$$ <br>
p and q also have the same bit length so they will be somewhat close to $$n^{0.5}$$ <br>
(E.g. $$n^{0.49} < p < n^{0.5} < q < n^{0.51}$$) <br>
It so happens that using beta=0.49 will compute x mod p where $$p \geq n^{0.49}$$ <br>
Note that $$x = p^2 + 1337p + delta$$ so $$x \ (mod \ p) = p^2 + 1337p + delta \ (mod \ p) = delta$$ <br>
So small_roots will return delta! This lets us choose the bounds, delta is a 64 bit integer so our bound should be $$2^{64}$$.

```python
PR.<x> = PolynomialRing(Zmod(n))
f = pow(2,e,n)*(x**3) + pow(3,e,n)*(x**2) + pow(5,e,n)*x + pow(7,e,n) - val
delta = small_roots(f, X=2^64, beta=0.49)[0]
```

<br>

Next $$f(delta) \equiv 0 \ (mod \ p)$$, so p divides f(delta) and p can be recovered with gcd.

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
delta = small_roots(f, X=2^64, beta=0.49)[0]

p = gcd(int(f(delta)), n)
q = n//p

d = inverse(e, (p-1)*(q-1))
key = RSA.construct((int(n), int(e), int(d), int(p), int(q)))
flag = PKCS1_OAEP.new(key=key, hashAlgo=SHA256).decrypt(long_to_bytes(c))
print(flag)
#crew{m0dp_3qu4710n_l34d5_u5_f4c70r1n6}
```
