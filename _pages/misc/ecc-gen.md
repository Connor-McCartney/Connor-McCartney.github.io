---
permalink: /misc/ecc-gen
title: Generating Elliptic Curves with a given order
---

<br>

Here is some useful code for creating random curves - taken from <br>
<https://github.com/jvdsn/crypto-attacks/blob/f9bd04b8311aaed12ef807155efdcbd0230e669d/shared/ecc.py>

```py
from random import choice
from random import randrange
from Crypto.Util.number import getPrime

def generate_curve(gf, k, c=None):
    """
    Generates an Elliptic Curve given GF(q), k, and parameter c
    :param gf: the finite field GF(q)
    :param k: j / (j - 1728)
    :param c: an optional parameter c which is used to generate random a and b values (default: random element in Zmod(q))
    :return:
    """
    c_ = c if c is not None else 0
    while c_ == 0:
        c_ = gf.random_element()

    a = 3 * k * c_ ** 2
    b = 2 * k * c_ ** 3
    return EllipticCurve(gf, [a, b])

def hilbert_class_polynomial_roots(D, gf):
    """
    Computes the roots of H_D(X) mod q given D and GF(q).
    TODO: implement "Accelerating the CM method" by Sutherland.
    :param D: the CM discriminant (negative)
    :param gf: the finite field GF(q)
    :return: a generator generating the roots (values j)
    """
    assert D < 0 and (D % 4 == 0 or D % 4 == 1), "D must be negative and a discriminant"
    H = hilbert_class_polynomial(D)
    pr = gf["x"]
    for j in pr(H).roots(multiplicities=False):
        yield j

def solve_cm(D, q, c=None):
    """
    Solves a Complex Multiplication equation for a given discriminant D, prime q, and parameter c.
    :param D: the CM discriminant (negative)
    :param q: the prime q
    :param c: an optional parameter c which is used to generate random a and b values (default: random element in Zmod(q))
    :return: a generator generating elliptic curves in Zmod(q) with random a and b values
    """
    assert is_prime_power(q)

    gf = GF(q)
    if gf.characteristic() == 2 or gf.characteristic() == 3:
        return

    ks = []
    for j in hilbert_class_polynomial_roots(D, gf):
        if j != 0 and j != gf(1728):
            k = j / (1728 - j)
            yield generate_curve(gf, k, c)
            ks.append(k)

    while len(ks) > 0:
        for k in ks:
            yield generate_curve(gf, k, c)


def generate_with_trace_q(t, q, D=None, c=None):
    """
    Generates random elliptic curves for a specific trace of Frobenius and modulus.
    Note: this method may take a very long time if D is not provided.
    :param t: the trace of Frobenius
    :param q: the prime finite field modulus
    :param D: the (negative) CM discriminant to use (default: computed using t and q)
    :param c: the parameter c to use in the CM method (default: random value)
    :return: a generator generating random elliptic curves
    """
    assert t ** 2 < 4 * q, f"Trace {t} is outside Hasse's interval for GF({q})"

    if D is None:
        D = t ** 2 - 4 * q
        # We don't make D square-free because that removes solutions.
    else:
        assert (t ** 2 - 4 * q) % D == 0 and is_square((t ** 2 - 4 * q) // D), "Invalid values for t, q, and D."

    for E in solve_cm(D, q, c):
        if E.trace_of_frobenius() == t:
            yield E
        else:
            E = E.quadratic_twist()
            yield E


def generate_with_trace(t, q_bit_length, D=None, c=None):
    """
    Generates random elliptic curves for a specific trace of Frobenius and modulus bit length.
    :param t: the trace of Frobenius
    :param q_bit_length: the bit length of the modulus, used to generate a random q
    :param D: the (negative) CM discriminant to use (default: computed using t)
    :param c: the parameter c to use in the CM method (default: random value)
    :return: a generator generating random elliptic curves
    """
    if D is None:
        D = 11
        while D % 4 != 3 or t % D == 0:
            D = next_prime(D)
        D = int(-D)
    else:
        assert (-D) % 4 == 3 and t % (-D) != 0 and is_prime(-D), "Invalid values for t and D."

    v_bit_length = (q_bit_length + 2 - D.bit_length()) // 2 + 1
    assert v_bit_length > 0, "Invalid values for t and q bit length."

    while True:
        v = randrange(2 ** (v_bit_length - 1), 2 ** v_bit_length)
        q4 = t ** 2 - v ** 2 * D
        if q4.bit_length() - 2 == q_bit_length and q4 % 4 == 0 and is_prime(q4 // 4):
            q = q4 // 4
            yield from generate_with_trace_q(t, q, D, c)


def generate_with_order_q(m, q, D=None, c=None):
    """
    Generates random elliptic curves for a specific order and modulus.
    Note: this method may take a very long time if D is not provided.
    :param m: the order
    :param q: the prime finite field modulus
    :param D: the (negative) CM discriminant to use (default: computed using m and q)
    :param c: the parameter c to use in the CM method (default: random value)
    :return: a generator generating random elliptic curves
    """
    yield from generate_with_trace_q(q + 1 - m, q, D, c)


def generate_with_order(m, D=None, c=None):
    """
    Generates random elliptic curves for a specific order.
    The modulus bit length will always be approximately equal to the order bit length.
    Based on: Broeker R., Stevenhagen P., "Constructing Elliptic Curves of Prime Order"
    :param m: the order
    :param D: the (negative) CM discriminant to use (default: computed using m)
    :param c: the parameter c to use in the CM method (default: random value)
    :return: a generator generating random elliptic curves
    """

    def get_q(m, D, factors):
        for t in set(map(lambda sol: int(sol[0]), pari.qfbsolve(pari.Qfb(1, 0, -D), [4 * m, factors], 1))): 
            if is_prime(m + 1 - t):
                return m + 1 - t
            if is_prime(m + 1 + t):
                return m + 1 + t

    q = None
    print('factoring...')
    factors = factor(4*m)
    print(factors)
    if D is None:
        for D in range(7, 4 * m):
            if not (D % 4 == 0 or D % 4 == 3):
                continue

            q = get_q(m, -D, factors)
            if q is not None:
                break

        assert q is not None, "Unable to find appropriate D value for m."
        D = int(-D)
    else:
        q = get_q(m, D, factors)
        assert q is not None, "Invalid values for m and D."

    yield from generate_with_trace_q(q + 1 - m, q, D, c)


order = randint(0, 2**200)
for E in generate_with_order(order):
    print(E)
    a = E.a4()
    b = E.a6()
    p = int(str(E.base()).split()[-1])
    print(f"{a = }")
    print(f"{b = }")
    print(f"{p = }")
    break
```
