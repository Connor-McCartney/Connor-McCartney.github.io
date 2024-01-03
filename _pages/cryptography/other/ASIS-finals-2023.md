---
permalink: /cryptography/other/ASIS-finals-2023
title: ASIS finals 2023
---

<br>
<br>

[Challenge Files](https://github.com/Connor-McCartney/CTF_Files/tree/main/2023/ASIS-finals)

<br>

# tricare

<br>

We can simplify r using a lot of [product-to-sum](https://andymath.com/wp-content/uploads/2019/09/Product-and-Sum-Formulas-e1567457862597.jpg) substitutions:

$$r = 20 \sin^3(m)\cos^3(m) - 6\sin(m)\cos(m)(\sin^4(m) + \cos^4(m))$$

$$= 20 \cdot\sin(m)\cos(m) \cdot \sin(m)\sin(m) \cdot \cos(m)\cos(m) - 6 \cdot \sin(m)\cos(m) \cdot ((\sin(m)\sin(m))^2 + (\cos(m)\cos(m))^2)$$

$$= 2 \cdot\sin(m)\cos(m) \cdot \left(10 \cdot \sin(m)\sin(m) \cdot \cos(m)\cos(m) - 3 \cdot ((\sin(m)\sin(m))^2 + (\cos(m)\cos(m))^2)\right)$$

$$= 2 \cdot \frac{\sin(2m)}{2} \cdot \left(10 \cdot  \frac{1 - \cos(2m)}{2} \cdot \frac{\cos(2m) + 1}{2} - 3 \cdot \left(\left(\frac{1 - \cos(2m)}{2}\right)^2 + \left(\frac{\cos(2m) + 1}{2}\right)^2\right) \right)$$

$$= \sin(2m) \cdot \left(\frac{10}{4} \cdot  (1 - \cos^2(2m)) - \frac{3}{4} \cdot (2 + 2\cos^2(2m))  \right)$$

$$=\sin(2m) \cdot \left(   \frac{10}{4} - \frac{10}{4}\cos^2(2m) - \frac{6}{4} - \frac{6}{4}\cos^2(2m)  \right)$$

$$=\sin(2m) \cdot ( 1  - 4\cos^2(2m) )$$

$$= \sin(2m) - 4\sin(2m)\frac{\cos(4m)+1}{2}$$

$$= -2\sin(2m)\cos(4m) -  \sin(2m)$$

$$= -2\frac{\sin(6m) - \sin(2m)}{2} -  \sin(2m)$$

$$= -\sin(6m)$$

<br>

Sub r in and we have:

$$t = \frac{1 - \cos(6m) + \text{seed} \cdot\sin(6m)}{\sin(6m) + \text{seed} \cdot (\cos(6m) + 1)}$$

[Yeet that into wolfram alpha](https://www.wolframalpha.com/input?i=%281+-+cos%286x%29+%2B+y+*+sin%286x%29%29+%2F+%28sin%286x%29+%2B+y+*+%28cos%286x%29%2B1%29%29) and we get:

$$t = \tan(3m)$$

<br>

Now sub t into s:

$$s = \frac{(\tan(3m))^3 - 3(\tan(3m))}{1 - 3(\tan(3m))^2}$$

<br>

Again, [yeet into wolfram alpha](https://www.wolframalpha.com/input?i=%28%28tan%283x%29%29%5E3+-+3%28tan%283x%29%29%29+%2F+%281+-+3%28tan%283x%29%5E2%29%29) and we get:

$$s = -\tan(9m)$$

If anyone has any proofs for those two identities you can msg me and I'll add them here.

ETA: found this <https://www.trans4mind.com/personal_development/mathematics/trigonometry/multipleAnglesRecursiveFormula.htm>

<br>

Rearranging:

$$\tan(-9m) = s$$

$$-9m = \arctan(s) + k\pi$$

$$0 = \arctan(s) + k\pi + 9m$$

<br>

Turning into vector equations for LLL should spit out m directly:

$$1 \begin{bmatrix} \arctan(s) \\ 1 \\ 0\end{bmatrix} + k \begin{bmatrix} \pi \\ 0 \\ 0\end{bmatrix} + m \begin{bmatrix} 9 \\ 0 \\ 1 \end{bmatrix}   = \begin{bmatrix} 0 \\ 1 \\ m \end{bmatrix}$$

<br>

```python
from Crypto.Util.number import *

precision = 1363
s = 4.4061969948574999706381252707706339596595993989993753525157058049520620878450909599070901658740035834714697099225869545917495720287359577329698453888804452908560270310064490162218842432355207070730163222140239639986509963808182579875037244043013930898502696038143722917574699793054569551851806943599434585896730793457949140792425837528999663586881638690611528789842156130245622849852139290458664441887058153106
at = arctan(s)
pi = pi.n(precision)

L = matrix(QQ, [
    [9,  0, 1], 
    [pi, 0, 0], 
    [at, 1, 0]
])
W = diagonal_matrix([2**precision, 2**679, 1])
L = (L*W).LLL() / W

for row in L:
    try:
        _, _, m = row
        print(long_to_bytes(int(m)).decode())
    except:
        continue

# ASIS{tr190n0M3tr1c_fuNct10ns_pr0dUc3_r3suLts_1Z_h4rd_t0_r3v3rsE_1nt0_1ts_Or1g!n4l!!?}
```

---

<br>

Alternative coppersmith solve:

```python
from Crypto.Util.number import *
import itertools

def defund_multivariate(f, bounds, m=1, d=None):
    if not d:
        d = f.degree()
    R = f.base_ring()
    N = R.cardinality()
    #f /= f.coefficients().pop(0)
    f = f.change_ring(ZZ)
    G = Sequence([], f.parent())
    for i in range(m+1):
        base = N^(m-i) * f^i
        for shifts in itertools.product(range(d), repeat=f.nvariables()):
            g = base * prod(map(power, f.variables(), shifts))
            G.append(g)
    B, monomials = G.coefficient_matrix()
    monomials = vector(monomials)
    factors = [monomial(*bounds) for monomial in monomials]
    for i, factor in enumerate(factors):
        B.rescale_col(i, factor)
    B = B.dense_matrix().LLL()
    B = B.change_ring(QQ)
    for i, factor in enumerate(factors):
        B.rescale_col(i, 1/factor)
    H = Sequence([], f.parent().change_ring(QQ))
    for h in filter(None, B*monomials):
        H.append(h)
        I = H.ideal()
        if I.dimension() == -1:
            H.pop()
        elif I.dimension() == 0:
            roots = []
            for root in I.variety(ring=ZZ):
                root = tuple(R(root[var]) for var in f.variables())
                roots.append(root)
            return roots
    return []

precision = 1363
s = 4.4061969948574999706381252707706339596595993989993753525157058049520620878450909599070901658740035834714697099225869545917495720287359577329698453888804452908560270310064490162218842432355207070730163222140239639986509963808182579875037244043013930898502696038143722917574699793054569551851806943599434585896730793457949140792425837528999663586881638690611528789842156130245622849852139290458664441887058153106
at = arctan(s)
pi = pi.n(precision)

R = RealField(precision)
PR.<x> = PolynomialRing(R)
f =  (x^3 - 3*x) - s*(1-3*x^2)
for t, _ in f.roots():
    at = arctan(t)
    M = 2**precision
    PR.<x, k> = PolynomialRing(Zmod(2**precision))
    f =  int(at*M) + k * int(pi*M) + x
    roots = defund_multivariate(f, bounds=(2**679, 2**679), m=1, d=2)
    if roots == []:
        continue
    k = R(roots[0][1])
    x = int(k*pi + at)
    m = x // 3 + 1
    flag = long_to_bytes(m)
    if b"ASIS" in flag:
        print(flag)
```
