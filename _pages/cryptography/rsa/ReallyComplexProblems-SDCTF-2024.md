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


Author's Solution:

<br>

<https://cseweb.ucsd.edu/~nadiah/papers/ideal-coppersmith/ideal-coppersmith-ics-slides.pdf>

<https://ia803007.us.archive.org/2/items/arxiv-1008.1284/1008.1284.pdf>

```python
def coefficient_poly(g, m):
    assert(g.degree() <= m)
    unpadded_result = g.coefficients(sparse=False)
    result = unpadded_result + [0] * (m - len(unpadded_result))
    return vector(result)

# get block matrix canonical embedding of Gaussian integer z, scaled with lmbds 
def get_block_matrix(z, s, limits):
    return matrix(ZZ, [[limits[0]^s * z.real(), limits[1]^s * z.imag()], [-1 * limits[0]^s * z.imag(), limits[1]^s * z.real()]])

def complex_coppersmith(f, N, limits, k=3, t=3):
    x = f.parent().gen(0)
    d = f.degree()
    m = d * k + t
    blocks = []
    for i in range(k):
        for j in range(d):
            poly = x^j * f^i * N^(k-i)
            poly_coeffs = coefficient_poly(poly, m)
            block_matrix_row = [get_block_matrix(z, s, limits) for (s, z) in enumerate(poly_coeffs)]
            blocks.append(block_matrix_row)
    for j in range(t):
        poly = x^j * f^k
        poly_coeffs = coefficient_poly(poly, m)
        block_matrix_row = [get_block_matrix(z, s, limits) for (s, z) in enumerate(poly_coeffs)]
        blocks.append(block_matrix_row)
    
    M = block_matrix(blocks)
    
    print('LLL...')
    M_reduced = M.LLL()
    print('LLL done')
    v = M_reduced[0]

    Q = 0
    for (s, i) in enumerate(list(range(0, len(v), 2))):
        z = v[i] / (limits[0]^s) + v[i+1] / (limits[1]^s) * I
        Q += z * x^s
    return Q


PR.<x> = PolynomialRing(I.parent())

N = -117299665605343495500066013555546076891571528636736883265983243281045565874069282036132569271343532425435403925990694272204217691971976685920273893973797616802516331406709922157786766589075886459162920695874603236839806916925542657466542953678792969287219257233403203242858179791740250326198622797423733569670 + 617172569155876114160249979318183957086418478036314203819815011219450427773053947820677575617572314219592171759604357329173777288097332855501264419608220917546700717670558690359302077360008042395300149918398522094125315589513372914540059665197629643888216132356902179279651187843326175381385350379751159740993*I
a = (10^70 * 1671911043329305519973004484847472037065973037107329742284724545409541682312778072234 
      + 10^68 * I * 193097758392744599866999513352336709963617764800771451559221624428090414152709219472155 
     )

f = x + a
Q = complex_coppersmith(f, N, [10^70, 10^68], k=10, t=10)
p = a + Q.roots()[0][0]
p_norm = int(p.norm())

q = N / p
q_norm = int(q.norm())
assert is_prime(p_norm) and is_prime(q_norm)
print(f"{p = }")
print()
print(f"{q = }")

d = pow(65537, -1, (p_norm-1)*(q_norm-1))
print(f"{d = }")
```

<br>

```python
from Crypto.Util.number import long_to_bytes
from fractions import Fraction

class GaussianRational:
    def __init__(self, real: Fraction, imag: Fraction):
        assert(type(real) == Fraction)
        assert(type(imag) == Fraction)
        self.real = real
        self.imag = imag
    def conjugate(self):
        return GaussianRational(self.real, self.imag * -1)
    def __sub__(self, other):
        return GaussianRational(self.real - other.real, self.imag - other.imag)
    def __mul__(self, other):
        return GaussianRational(self.real * other.real - self.imag * other.imag, self.real * other.imag + self.imag * other.real)
    def __truediv__(self, other):
        divisor = (other.conjugate() * other).real
        dividend = other.conjugate() * self
        return GaussianRational(dividend.real / divisor, dividend.imag / divisor)
    def __mod__(self, other):
        x = self/other
        from builtins import round # sage round gives error
        y = GaussianRational(Fraction(round(x.real)), Fraction(round(x.imag)))
        z = y*other
        return self - z
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
    def __repr__(self):
        return f"{self.real}\n+ {self.imag}i"

Nr = -117299665605343495500066013555546076891571528636736883265983243281045565874069282036132569271343532425435403925990694272204217691971976685920273893973797616802516331406709922157786766589075886459162920695874603236839806916925542657466542953678792969287219257233403203242858179791740250326198622797423733569670
Ni = 617172569155876114160249979318183957086418478036314203819815011219450427773053947820677575617572314219592171759604357329173777288097332855501264419608220917546700717670558690359302077360008042395300149918398522094125315589513372914540059665197629643888216132356902179279651187843326175381385350379751159740993
N = GaussianRational(Fraction(Nr), Fraction(Ni))

cr =  49273345737246996726590603353583355178086800698760969592130868354337851978351471620667942269644899697191123465795949428583500297970396171368191380368221413824213319974264518589870025675552877945771766939806196622646891697942424667182133501533291103995066016684839583945343041150542055544031158418413191646229
ci = -258624816670939796343917171898007336047104253546023541021805133600172647188279270782668737543819875707355397458629869509819636079018227591566061982865881273727207354775997401017597055968919568730868113094991808052722711447543117755613371129719806669399182197476597667418343491111520020195254569779326204447367
ciphertext = GaussianRational(Fraction(cr), Fraction(ci))

d = 30705973973835235992739087828101768569215095753086514399416188103137352654353724728125570074746522375538743105397510478629112440237039337250842792480917283649309771731175188045155475150314591252978430919085042195515139124812828180933550636311642065345801072903712714029507212283606481028185813874644439285781989249219379828768474823905738491256198490415036794186563705524843094958152895261408443884101452109153236904087336150045117185424332381579003650860532756694087620421318341125335785812528507963724859404731954587684312692321609646807297550689079889143734703514155805953902185062538036062876493414544714132851233
flag = pow(ciphertext, d, N)
print(long_to_bytes(int(flag.real)) + long_to_bytes(int(flag.imag)))

# SDCTF{lll_15_k1ng_45879340409310}
```
