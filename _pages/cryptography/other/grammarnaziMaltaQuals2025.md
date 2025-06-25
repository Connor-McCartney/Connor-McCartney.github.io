---
permalink: /cryptography/other/grammarnaziMaltaQuals2025
title: grammar_nazi - Malta Quals 2025
---


<br>

<br>

Challenge: 

<https://github.com/sajjadium/ctf-archives/tree/main/ctfs/MaltaCTF/2025/Quals/crypto/grammar_nazi>

(by Neobeo)

```python
from Crypto.Util.number import *

FLAG = 'maltactf{???????????????????????????????}'
assert len(FLAG) == 41

p = getPrime(128)
q = getPrime(128)
N = p * q
e = 65537

m = f'The flag is {FLAG}'
c = pow(bytes_to_long(m.encode()), e, N)

# ERROR: Sentences should end with a period.
m += '.'
c += pow(bytes_to_long(m.encode()), e, N)

# All good now!
print(f'{N = }')
print(f'{c = }')

'''
N = 83839453754784827797201083929300181050320503279359875805303608931874182224243
c = 32104483815246305654072935180480116143927362174667948848821645940823281560338
'''
```

<br>

<br>

Solve:

Modulus is 256 bits, and neobeo makes an unknown section barely under that:

```python
>>> 8*len('???????????????????????????????')
248
```


```python
from Crypto.Util.number import *

FLAG = 'maltactf{???????????????????????????????}'
assert len(FLAG) == 41
m = f'The flag is {FLAG}'

M = bytes_to_long(m.encode())
t = 256**32 * bytes_to_long(b'The flag is maltactf{') + ord('}')
x = bytes_to_long(b'???????????????????????????????')
assert M == 256*x + t

p = getPrime(128)
q = getPrime(128)
N = p * q
e = 65537

c = pow(bytes_to_long(m.encode()), e, N)
m += '.'
c += pow(bytes_to_long(m.encode()), e, N)

assert c == (pow(M, e, N) + pow(256*M + ord('.'), e, N))
assert c == (pow(256*x + t, e, N) + pow(256*(256*x+t) + ord('.'), e, N))

PR.<X> = PolynomialRing(Zmod(N))
f = (256*X + t)**e + (256*(256*X+t) + ord('.'))**e - c
assert f(X=x) == 0
```

<br>

We obtain 1 equation mod N with 1 unknown... just call .roots() right?

No, with the binomials expanded to exponent 65537 it's too slow....

<br>

<br>


Option 1: 

pari's polrootsmod is not bad, ~3 mins total to solve

```python
from Crypto.Util.number import *
proof.all(False)

c = 32104483815246305654072935180480116143927362174667948848821645940823281560338
e = 65537
N = 83839453754784827797201083929300181050320503279359875805303608931874182224243
p = 302904819256337380397575865141537456903
q = 276784813000398431755706235529589161781
assert p*q == N
t = 256**32 * bytes_to_long(b'The flag is maltactf{') + ord('}')

def solve(prime_factor):
    PR.<X> = PolynomialRing(GF(prime_factor))
    f = (256*X + t)**e + (256*(256*X+t) + ord('.'))**e - c
    coeffs = list(f.coefficients(sparse=False))
    pari_f = pari(pari.Polrev(coeffs, 'x'))  
    roots = pari_f.polrootsmod()
    return roots

roots_mod_p = solve(p)
print(roots_mod_p)
roots_mod_q = solve(q)
print(roots_mod_q)

for pp in roots_mod_p:
    for qq in roots_mod_q:
        flag = long_to_bytes(int(crt([Integer(pp), Integer(qq)], [p,q])))
        try:
            print(flag.decode())
        except:
            pass
```

```
$ time sage solve.sage
[Mod(53126147214111282958792288694359104369, 302904819256337380397575865141537456903), Mod(102676800749335072686760682938685158581, 302904819256337380397575865141537456903), Mod(279567651354133789096331775415225344056, 302904819256337380397575865141537456903)]~
[Mod(57366902235977733831484439313893621575, 276784813000398431755706235529589161781), Mod(128540216454252556772445981320102598547, 276784813000398431755706235529589161781)]~
Ferm4ts_littl3_polyn0mial_tr1ck

real	2m46.949s
```


Option 2: 

a polynomial GCD trick, takes under a minute

<https://adib.au/2025/lance-hard/#part-3-solve-the-polynomial>

```python
def solve(prime_factor):
    PR.<X> = PolynomialRing(GF(prime_factor))
    f = (256*X + t)**e + (256*(256*X+t) + ord('.'))**e - c
    g = pow(X, prime_factor, f) - X
    roots = [r for r, _ in f.gcd(g).roots()]
    return roots
```
