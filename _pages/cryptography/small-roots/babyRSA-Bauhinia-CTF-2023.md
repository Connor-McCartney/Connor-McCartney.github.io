---
permalink: /cryptography/small-roots/babyRSA-Bauhinia-CTF-2023
title: grhkm's babyRSA - Bauhinia CTF 2023
---

<br>


# Challenge:

<br>

```python
from math import gcd
from Crypto.Util.number import getPrime, getRandomNBitInteger, bytes_to_long
from secret import flag

lcm = lambda u, v: u*v//gcd(u, v)

bits = 1024
given = bits // 5
e_bits = bits // 12

mask = (1 << given) - 1

while True:
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    N = p * q

    if N.bit_length() != bits:
        continue

    l = lcm(p - 1, q - 1)
    e = getRandomNBitInteger(e_bits)

    if gcd(e, l) > 1:
        continue

    d = pow(e, -1, l)

    dp = int(d % (p - 1))
    dq = int(d % (q - 1))

    break

l_dp = dp & mask
l_dq = dq & mask

print(f'{N = }')
print(f'{e = }')
print(f'{l_dp = }')
print(f'{l_dq = }')

flag = bytes_to_long(flag)

ct = pow(flag, e, N)
print(f'{ct = }')
```

<br>

```python
N = 96446191626393604009054111437713980755082681332020571709789032122186639773874753631630024642568257679734714430483780317122960230235124140242511126339536047435591010087751700582288534654352742251068909342986464462021206713195415006300821397979265537607226612724482984235104418995222711966835565604156795231519
e = 21859725745573183363159471
l_dp = 5170537512721293911585823686902506016823042591640808668431139
l_dq = 2408746727412251844978232811750068549680507130361329347219033
ct = 22853109242583772933543238072263595310890230858387007784810842667331395014960179858797539466440641309211418058958036988227478000761691182791858340813236991362094115499207490244816520864518250964829219489326391061014660200164748055767774506872271950966288147838511905213624426774660425957155313284952800718636
```


<br><br>

# Solve:


So we are given the lower bits of dp and dq.
A google search leads to this paper "Factoring with Only a Third of the Secret CRT-Exponents":

<https://eprint.iacr.org/2022/271.pdf>

<br>

We begin with 4 equations:


$$dp = h\_dp \cdot 2^i + l\_dp$$

$$dq = h\_dq \cdot 2^i + l\_dq$$

$$e \cdot dp = k(p-1) + 1$$

$$e \cdot dq = l(q-1) + 1$$


```python
i = given
l_dp = dp & mask
l_dq = dq & mask
h_dp = (dp - l_dp) >> i
k = (e*dp-1) // (p-1)
l = (e*dq-1) // (q-1)
```

<br><br>

Section 3.2 of the paper gives us a polynomial with k,l as unknowns:

```python
PR.<x, y> = PolynomialRing(Zmod(e*2**i), 2)
A = e*(l_dp + l_dq) - e**2 * l_dp * l_dq - 1
f = (N-1)*x*y - (e*l_dq-1)*x - (e*l_dp-1)*y + A
assert int(f(x=k, y=l)) == 0
```

<br><br>

Then Section 3.3 gives us a polynomial with h_dp as the unknown (mod p). And since f(h_dp) divides p, we can recover p with GCD:

```python
PR.<x> = PolynomialRing(Zmod(N))
a = (e*l_dp + k - 1) * pow(e*2**i, -1, k*N)
f = x + a
assert int(f(x=h_dp)) % p == 0
p = gcd(int(f(x=h_dp)), N)
assert is_prime(p)
```

<br><br>

So now the TLDR is try solve the first equation with bivariate coppersmith and second equation with univariate coppersmith. 

<br>

I increased the given bits (from 204 to 280) and got a proof of concept working using Defund's implementation for bivariate and sage's builtin small_roots for univariate:

<br>

<https://github.com/defund/coppersmith/blob/master/coppersmith.sage>

<br>

Note in Defund's just delete this line

```python
f /= f.coefficients().pop(0)
```

<br><br>

```python
from Crypto.Util.number import getPrime, getRandomNBitInteger, bytes_to_long
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

lcm = lambda u, v: u*v//gcd(u, v)
bits = 1024
given = 280 #bits // 5
e_bits = bits // 12
mask = (1 << given) - 1

while True:
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    N = p * q
    if N.bit_length() != bits:
        continue
    l = lcm(p - 1, q - 1)
    e = getRandomNBitInteger(e_bits)
    if gcd(e, l) > 1:
        continue
    d = pow(e, -1, l)
    dp = int(d % (p - 1))
    dq = int(d % (q - 1))
    try:
        k = (e*dp-1) // (p-1)
        tmp = pow(e*2**given, -1, k*N) # just added to get test cases where the inverse exists
    except:
        continue
    break

i = given
l_dp = dp & mask
l_dq = dq & mask
#h_dp = (dp - l_dp) >> i
#k = (e*dp-1) // (p-1)
#l = (e*dq-1) // (q-1)

PR.<x, y> = PolynomialRing(Zmod(e*2**i), 2)
A = e*(l_dp + l_dq) - e**2 * l_dp * l_dq - 1
f = (N-1)*x*y - (e*l_dq-1)*x - (e*l_dp-1)*y + A
k, l = defund_multivariate(f, bounds=(e,e), m=3, d=4)[0]
k, l = int(k), int(l)
assert int(f(x=k, y=l)) == 0

PR.<x> = PolynomialRing(Zmod(N))
a = (e*l_dp + k - 1) * pow(e*2**i, -1, k*N)
f = x + a
h_dp = f.small_roots(X=2**(512-i), beta=0.4, epsilon=0.038)[0]
assert int(f(x=h_dp)) % p == 0
p = gcd(int(f(x=h_dp)), N)
assert is_prime(p)
```

<br><br>


If we plug in the given challenge data then we can get k and l successfully:

```python
import itertools

def defund_multivariate(f, bounds, m=1, d=None):
	...

i = 204
N = 96446191626393604009054111437713980755082681332020571709789032122186639773874753631630024642568257679734714430483780317122960230235124140242511126339536047435591010087751700582288534654352742251068909342986464462021206713195415006300821397979265537607226612724482984235104418995222711966835565604156795231519
e = 21859725745573183363159471
l_dp = 5170537512721293911585823686902506016823042591640808668431139
l_dq = 2408746727412251844978232811750068549680507130361329347219033

PR.<x, y> = PolynomialRing(Zmod(e*2**i), 2)
A = e*(l_dp + l_dq) - e**2 * l_dp * l_dq - 1
f = (N-1)*x*y - (e*l_dq-1)*x - (e*l_dp-1)*y + A
k, l = defund_multivariate(f, bounds=(e,e), m=3, d=4)[0]
print(k, l)
# 12177905682444242771542873 4277124735150641724212759
```

<br>

However... when we have to decrease the given bits again then sage's small_roots stops finding solutions for h_dp...

<br>

So we need a better lattice, I actually found one of the author's code:

<br>

<https://github.com/juliannowakowski/crtrsa-small-e-pke/blob/main/implementation_new_attack.sage>

<br>

And was able to use part of that:

```python
from Crypto.Util.number import long_to_bytes

def solve(f, X, m, t): 
    F = []
    S = []
    for j in range(m+1):
        h = f^j*k^(m-j)*N^(max(0,t-j))
        F.append(h)
        S.append(x^j)
    MAT = Matrix(ZZ, len(F))
    for i in range(len(F)):
        f = F[i]
        f = f(x*X)
        coeffs = (f.coefficients())
        for j in range(len(coeffs), len(F)):
            coeffs.append(0)
        coeffs = vector(coeffs)
        MAT[i] = coeffs
    MAT = MAT.LLL()
    ret = []
    for j in range(len(F)):
        f = 0
        for i in range(len(S)):
            f += MAT[j,i]//S[i](X)*S[i]
            roots = f.roots()
            if roots != []:
                ret.append(roots[0][0])
        return ret

i = 204
N = 96446191626393604009054111437713980755082681332020571709789032122186639773874753631630024642568257679734714430483780317122960230235124140242511126339536047435591010087751700582288534654352742251068909342986464462021206713195415006300821397979265537607226612724482984235104418995222711966835565604156795231519
e = 21859725745573183363159471
l_dp = 5170537512721293911585823686902506016823042591640808668431139
l_dq = 2408746727412251844978232811750068549680507130361329347219033
ct = 22853109242583772933543238072263595310890230858387007784810842667331395014960179858797539466440641309211418058958036988227478000761691182791858340813236991362094115499207490244816520864518250964829219489326391061014660200164748055767774506872271950966288147838511905213624426774660425957155313284952800718636
k = 12177905682444242771542873

R.<x> = QQ[]
a = (e*l_dp + k - 1) * pow(e*2**i, -1, k*N)
f = x + a

for h_dp in solve(f, X=2**(512-i), m=20, t=10):
    p = gcd(int(f(x=h_dp)), N)
    if is_prime(p):
        q = N//p
        d = pow(e, -1, (p-1)*(q-1))
        flag = int(pow(ct, d, N))
        print(long_to_bytes(flag))
        break

# b6actf{y0u_mu5t_b3_c0nv1nc3d_th4t_lgn/5_is_gr34t3r_th4n_lgn/4_n0w}
```

ETA author writeup: <https://github.com/grhkm21/CTF-challenges/blob/master/Bauhinia-CTF-2023/grhkm's%20babyRSA/sol/solve.sage>
