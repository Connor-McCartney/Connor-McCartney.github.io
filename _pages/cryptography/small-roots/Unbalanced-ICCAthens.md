---
permalink: /cryptography/small-roots/Unbalanced-ICCAthens
title: Unbalanced - ICC Athens
---

<br>

Challenge:

```python
from Crypto.Util.number import bytes_to_long, getPrime

def gen_keys(n_bits, p_bits, d_bits):
    q_bits = n_bits - p_bits
    p, q = getPrime(p_bits), getPrime(q_bits)
    N, phi = p*q, (p-1)*(q-1)
    while True:
        d = getPrime(d_bits)
        if d > N**0.292:
            break
    e = pow(d,-1,phi)
    return (N, e), (N, d)

def encrypt_flag(plaintext, pub):
    N, e = pub
    m = bytes_to_long(plaintext)
    return pow(m, e, N)

if __name__ == '__main__':
    with open("flag.txt", "rb") as f:
        flag = f.read().strip()

    n_bits = 1024
    p_bits = 256
    d_bits = 300
    pub, priv = gen_keys(n_bits, p_bits, d_bits)
    c = encrypt_flag(flag, pub)

    print(f"N = {hex(pub[0])}")
    print(f"e = {hex(pub[1])}")
    print(f"c = {hex(c)}")
```

<br>

Solve:

```python
def poly_sub(f, x, y):
    # https://gist.github.com/maple3142/0bb20789d7372b7e0e822d1b91ca7867
    Q = f.parent().quotient(x - y)
    return Q(f).lift()

N = 0x7506dad690d57202571d4138e6743e22834072087ef1f81f227409dda108854f2f10c23150dcfbe79940effde0603f64f77f8c123f6ad27ee0ebb3665de8cdb46ced5d2c69f4d9170d406fd93466f8400001b20ea8d084bbb06b28b0ca3782ca2bd92ac012d08103e3477f8ff83c836ebbda570a803bb5b0611b9b285188da53
e = 0x480fe3b95d6ebadae2a222b6161b8aa0cbb61e0571da3658dac4cf174c7670514c70d8b337408bac467d6a39804efb35394f6d83941fa2d25ca542f630db5b54efaf347062fb828cb7473728de0510f3b27b906c9dd056f77d1ceb0fb249fcc5fe4ee219be82cdb6cee2578b8fa8ad7b489ee45edff4349c4a03af42cc232f65
c = 0x24581cf0e782e1d6b9d6337e26d87ba16fbf8e5887b83522738769ffa59b38f76eafa61fe9a373948677101f5abe2a4e4032b11ff1c903fe9a0368d07212706bdb4cf24532df6819570ef6935fd3aa5e25f4f65c35a1d6362c8dc3eef95ec15ede94d2acf5ce15cfb81c37bcda4a83660006898f07bf40b072d9382a63b5ab4b
m, t, a = 5, 5, 0
bounds = (2**300, 2**256, 2**768)

R.<x, y, z> = PolynomialRing(ZZ)
A = N + 1
f = 2 + x*(A - y - z) 
polys = Sequence([], R)

# https://link.springer.com/chapter/10.1007/3-540-44448-3_2
for k in range(m):
    for i in range(1, m-k+1):
        for b in range(2):
            g = e^(m-k) * x^i * y^a * z^b * f^k 
            g = poly_sub(g, y*z, N)
            polys.append(g)
            
for k in range(m+1):
    for j in range(t+1):
        h = e^(m-k) * y^(a+j) * f^k 
        h = poly_sub(h, y*z, N)
        polys.append(h)

B, monomials = polys.coefficients_monomials()
W = diagonal_matrix([mon(*bounds) for mon in monomials])
B = (B*W).dense_matrix().LLL()/W
H = list(B*monomials)

for i in reversed(range(len(H))):
    print(i)
    try:
        roots = Ideal(H[:i]).groebner_basis()[0].univariate_polynomial().roots()
        print(roots)
        p = max(roots)[0]
        q = N//p
        assert p*q == N
    except:
        continue
    break
print(bytes.fromhex(f'{int(pow(c, pow(e, -1, (p-1)*(q-1)), N)):x}'))
```
