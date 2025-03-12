---
permalink: /cryptography/other/NonZeroKnowledgeProof-ECSC
title: Non Zero Knowledge Proof - ECSC
---

<br>
<br>

Challenge:

<https://hack.cert.pl/challenge/nzkp>

```python
import itertools
import sys

import random
import string
from Crypto.Util.number import getPrime, bytes_to_long
from functools import reduce


################ BOILERPLATE, YOU CAN IGNORE THIS ################

def multiply(values):
    """
    Multiply values on the list
    :param values: list of values
    :return: a*b*c*d...
    """
    import functools
    return functools.reduce(lambda x, y: x * y, values, 1)


def solve_crt(residue_and_moduli):
    """
    Solve CRT for given modular residues and modulus values, eg:
    x = 1 mod 3
    x = 2 mod 4
    x = 3 mod 5
    x = 58
    residue_and_moduli = [(1,3), (2,4), (3,5)]
    :param residue_and_moduli: list of pairs with (modular residue mod n, n)
    :return: x
    """
    residues, moduli = zip(*residue_and_moduli)
    N = multiply(moduli)
    Nxs = [N // n for n in moduli]
    ds = [modinv(N // n, n) for n in moduli]
    mults = [r * Nx * d for r, Nx, d in zip(residues, Nxs, ds)]
    return reduce(lambda x, y: x + y, mults) % N


def extended_gcd(a, b):
    """
    Calculate extended greatest common divisor of numbers a,b
    :param a: first number
    :param b: second number
    :return: gcd(a,b) and remainders
    """

    def copysign(a, b):
        return a * (1 if b >= 0 else -1)

    lastrem, rem = abs(a), abs(b)
    x, lastx, y, lasty = 0, 1, 1, 0
    while rem:
        lastrem, (quotient, rem) = rem, divmod(lastrem, rem)
        x, lastx = lastx - quotient * x, x
        y, lasty = lasty - quotient * y, y
    return lastrem, copysign(lastx, a), copysign(lasty, b)


def gcd(a, b):
    """
    Return simple greatest common divisor of a and b
    :param a:
    :param b:
    :return: gcd(a,b)
    """
    return extended_gcd(a, b)[0]


def modinv(x, y):
    """
    Return modular multiplicative inverse of x mod y.
    It is a value d such that x*d = 1 mod y
    :param x: number for which we want inverse
    :param y: modulus
    :return: modinv if it exists
    """
    return extended_gcd(x, y)[1] % y


def modular_sqrt_composite(c, factors):
    """
    Calculates modular square root of composite value for given all modulus factors
    For a = b^2 mod p*q*r*m... calculates b
    :param c: residue
    :param factors: list of modulus prime factors
    :return: all potential root values
    """
    n = multiply(factors)
    roots = [[(modular_sqrt(c, x), x), (x - modular_sqrt(c, x), x)] for x in factors]
    solutions = []
    for x in itertools.product(*roots):
        solution = solve_crt(list(x))
        solutions.append(solution)
        assert solution ** 2 % n == c
    return solutions


def modular_sqrt(a, p):
    """
    Calculates modular square root with prime modulus.
    For a = b^2 mod p calculates b
    :param a: residue
    :param p: modulus
    :return: root value
    """
    if legendre_symbol(a, p) != 1:
        return 0
    elif a == 0:
        return 0
    elif p == 2:
        return p
    elif p % 4 == 3:
        return pow(a, (p + 1) // 4, p)
    s = p - 1
    e = 0
    while s % 2 == 0:
        s //= 2
        e += 1
    n = 2
    while legendre_symbol(n, p) != -1:
        n += 1
    x = pow(a, (s + 1) // 2, p)
    b = pow(a, s, p)
    g = pow(n, s, p)
    r = e
    while True:
        t = b
        m = 0
        for m in range(r):
            if t == 1:
                break
            t = pow(t, 2, p)
        if m == 0:
            return x
        gs = pow(g, 2 ** (r - m - 1), p)
        g = (gs * gs) % p
        x = (x * gs) % p
        b = (b * g) % p
        r = m


def legendre_symbol(a, p):
    ls = pow(a, (p - 1) // 2, p)
    return -1 if ls == p - 1 else ls


def pad(flag, nbits):
    missing = nbits // 8 - len(flag)
    return flag + ''.join(random.choices(string.ascii_letters, k=missing)).encode()


################ END OF BOILERPLATE ################

def main():
    bits = 1024
    p = getPrime(bits)
    q = getPrime(bits)
    n = p * q
    print(
        "Interactive ZKP based on Rabin cryptosystem. Provide encrypted challenge value (r^2 mod n such that r%10 == 0) and I will decrypt it to prove I have the private key.")
    print(n)
    sys.stdout.flush()
    for i in range(32):
        try:
            c = int(input("challenge>\n"))
            roots = modular_sqrt_composite(c, [p, q])
            valid_decryption = [r for r in roots if r % 10 == 0]
            print(valid_decryption[0])
            sys.stdout.flush()
        except:
            print("Please provide only challenges ending with 0, so I can distinguish the real root!")
            sys.stdout.flush()
            return
    print(pow(bytes_to_long(pad(open("flag.txt", "rb").read(), bits)), 2, n))
    sys.stdout.flush()


main()
```

<br>

<br>

<br>

<br>

<br>

Solve:

<https://crypto.stackexchange.com/questions/96060/rabin-cryptosystem-chosen-ciphertext-attack>

