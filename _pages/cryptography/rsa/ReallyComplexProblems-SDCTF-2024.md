---
permalink: /cryptography/rsa/ReallyComplexProblems-SDCTF-2024
title: ReallyComplexProblems - SDCTF 2024
---

<br>

[Challenge Files](https://github.com/Connor-McCartney/CTF_Files/tree/main/2024/SDCTF/ReallyComplexProblems)

<br>

Given Ni, Nr, MSB of pi and MSB of pr, we have to factor N_. 

```python
    Nr = int(N.real)
    Ni = int(N.imag)
    pr = int(p.real)
    pi = int(p.imag)
    qr = int(q.real)
    qi = int(q.imag)

    assert Nr == pr*qr - pi*qi
    assert Ni == pr*qi + pi*qr

    p_ = pi**2 + pr**2
    q_ = qi**2 + qr**2
    N_ = Ni**2 + Nr**2
    assert is_prime(p_) and is_prime(q_)
    assert p_ * q_ == N_
```

<br>

Tried bivariate coppersmith but seems something better is needed:

```python
from sage.all import *
from secrets import randbits
from Crypto.Util.number import *
from fractions import Fraction
from binascii import hexlify
import itertools
from sage.rings.polynomial.multi_polynomial_sequence import PolynomialSequence
load('https://raw.githubusercontent.com/Connor-McCartney/coppersmith/main/coppersmith.sage')
from tqdm import *


def small_roots(f, bounds, m, d):
    if d is None:
        d = f.degree()

    R = f.base_ring()
    N = R.cardinality()
    f_ = (f // f.lc()).change_ring(ZZ)
    f = f.change_ring(ZZ)
    l = f.lm()

    M = []
    for k in range(m+1):
        M_k = set()
        T = set((f ** (m-k)).monomials())
        for mon in (f**m).monomials():
            if mon//l**k in T: 
                for extra in itertools.product(range(d), repeat=f.nvariables()):
                    g = mon * prod(map(power, f.variables(), extra))
                    M_k.add(g)
        M.append(M_k)
    M.append(set())

    shifts = PolynomialSequence([], f.parent())
    for k in range(m+1):
        for mon in M[k] - M[k+1]:
            g = mon//l**k * f_**k * N**(m-k)
            shifts.append(g)

    B, monomials = shifts.coefficients_monomials()
    monomials = vector(monomials)

    factors = [monomial(*bounds) for monomial in monomials]
    for i, factor in enumerate(factors):
        B.rescale_col(i, factor)

    try:
        B, _ = do_LLL_flatter(B)
    except:
        B = B.dense_matrix().LLL()

    B = B.change_ring(QQ)
    for i, factor in enumerate(factors):
        B.rescale_col(i, 1/factor)
    B = B.change_ring(ZZ)

    H = PolynomialSequence([h for h in B*monomials if not h.is_zero()])

    for i, (f1, f2) in (enumerate(itertools.combinations(H, r=2))):
        #if i>50:
        #    return []
        x, y = f.parent().gens()
        x = f1.parent()(x)
        y = f1.parent()(y)
        res = f1.resultant(f2,y).univariate_polynomial()
        if res == 0:
            continue
        rs = res.roots()
        if rs:
            x = rs[0][0]
            #print(f"{x = }")
            if x<0:
                continue
            y = f1.subs(x=x).univariate_polynomial().roots()[0][0]
            return (x, y)



class GaussianRational:
    def __init__(self, real: Fraction, imag: Fraction):
        assert(type(real) == Fraction)
        assert(type(imag) == Fraction)
        self.real = real
        self.imag = imag

    def conjugate(self):
        return GaussianRational(self.real, self.imag * -1)
    
    def __add__(self, other):
        return GaussianRational(self.real + other.real, self.imag + other.imag)
    
    def __sub__(self, other):
        return GaussianRational(self.real - other.real, self.imag - other.imag)
    
    def __mul__(self, other):
        return GaussianRational(self.real * other.real - self.imag * other.imag, self.real * other.imag + self.imag * other.real)

    def __truediv__(self, other):
        divisor = (other.conjugate() * other).real
        dividend = other.conjugate() * self
        return GaussianRational(dividend.real / divisor, dividend.imag / divisor)
    
    # credit to https://stackoverflow.com/questions/54553489/how-to-calculate-a-modulo-of-complex-numbers
    def __mod__(self, other):
        x = self/other
        from builtins import round # sage round gives error
        y = GaussianRational(Fraction(round(x.real)), Fraction(round(x.imag)))
        z = y*other
        return self - z
    
    # note: does not work for negative exponents
    # exponent is (non-negative) integer, modulus is a Gaussian rational
    def __pow__(self, exponent, modulo):
        shifted_exponent = exponent
        powers = self
        result = GaussianRational(Fraction(1), Fraction(0))
        while (shifted_exponent > 0):
            if (shifted_exponent & 1 == 1):
                result = (result * powers) % modulo
            shifted_exponent >>= 1
            powers = (powers * powers) % modulo
        return result
    
    def __eq__(self, other):
        if type(other) != GaussianRational: return False
        return self.imag == other.imag and self.real == other.real
    
    def __repr__(self):
        return f"{self.real}\n+ {self.imag}i"

# gets a Gaussian prime with real/imaginary component being n bits each
def get_gaussian_prime(nbits):
    while True:
        candidate_real = randbits(nbits-1) + (1 << nbits)
        candidate_imag = randbits(nbits-1) + (1 << nbits)
        if isPrime(candidate_real*candidate_real + candidate_imag*candidate_imag):
            candidate = GaussianRational(Fraction(candidate_real), Fraction(candidate_imag))
            return candidate

def generate_keys(nbits, e=65537):
    p = get_gaussian_prime(nbits)
    q = get_gaussian_prime(nbits)
    N = p*q
    p_norm = int(p.real*p.real + p.imag*p.imag)
    q_norm = int(q.real*q.real + q.imag*q.imag)
    tot = (p_norm - 1) * (q_norm - 1)
    d = pow(e, -1, tot)
    return ((N, e), (N, d), (p, q)) # (N, e) is public key, (N, d) is private key

def encrypt(message, public_key):
    (N, e) = public_key
    return pow(message, e, N)

def decrypt(message, private_key):
    (N, d) = private_key
    return pow(message, d, N)

if __name__ == "__main__":
    #flag = None
    #with open("flag.txt", "r") as f:
    #    flag = f.read()
    flag = "testflag"
    (public_key, _, primes) = generate_keys(512)
    (p, q) = primes
    (N, e) = public_key
    #print(f"N = {N}")
    #print(f"e = {e}")
    flag1 = flag[:len(flag) // 2].encode()
    flag2 = flag[len(flag) // 2:].encode()
    real = int(hexlify(flag1).decode(), 16)
    imag = int(hexlify(flag2).decode(), 16)
    message = GaussianRational(Fraction(real), Fraction(imag))
    ciphertext = encrypt(message, public_key)
    #print(f"ciphertext = {ciphertext}")
    #print(f"\n-- THE FOLLOWING IS YOUR SECRET KEY. DO NOT SHOW THIS TO ANYONE ELSE --")
    #print(f"p = {p}")
    #print(f"q = {q}")

    Nr = int(N.real)
    Ni = int(N.imag)
    pr = int(p.real)
    pi = int(p.imag)
    qr = int(q.real)
    qi = int(q.imag)
    N_ = Ni**2 + Nr**2
    p_ = pi**2 + pr**2


    known = 131

    pr_high = int(str(p.real)[:known])
    pi_high = int(str(p.imag)[:known])
    pr_low = int(str(p.real)[known:])
    pi_low = int(str(p.imag)[known:])
    print(f"{pr_low = }")
    print(f"{pi_low = }")

    # now to recover them
    b = 10**(155-known)
    PR = PolynomialRing(Zmod(N_), names=['x', 'y'])
    x, y = PR.gens()
    f = (pr_high*b+x)**2 + (pi_high*b+y)**2
    assert int(f(x=pr_low, y=pi_low)) % p_ == 0
    print(small_roots(f, bounds=(b, b), m=2, d=5))
```

<br>

