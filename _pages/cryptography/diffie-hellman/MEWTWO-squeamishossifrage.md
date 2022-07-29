---
permalink: /cryptography/diffie-hellman/MEWTWO-squeamishossifrage
title: MEWTWO - squeamishossifrage
---

<br>

[Challenge](https://github.com/zerosumsecurity/squeamishossifrage/tree/main/MEWTWO)

<br>

First we see n = p^2

The order of n is p(p-1)

p-1 = `2 * 3 * 5^2 * 17 * 257 * 641 * 1531 * 65537 * 490463 * 6700417 * 83594504224461495178038995336787794345391692724`

The largest factor is too big for regular Pohlig-Hellman. Omitting it also doesn't give the flag. So we must use the factor p. 

$$c \equiv g^x \ (mod\ p)$$

Now in <https://en.wikipedia.org/wiki/Okamoto%E2%80%93Uchiyama_cryptosystem> there is an isomorphism to an additive group:

$$L(z) = \frac{z-1}{p}$$

Then wikipedia gives

$$x = \frac{L((g^{(p-1)})^x)}{L(g^{(p-1)})}\ (mod\ p)$$

$$ \ \ = \frac{L((g^x)^{(p-1)})}{L(g^{(p-1)})}\ (mod\ p)$$

$$ \ = \frac{L(c^{(p-1)})}{L(g^{(p-1)})}\ (mod\ p)$$

<br>

```py
from sympy.ntheory.residue_ntheory import n_order, _discrete_log_trial_mul
from sympy.ntheory.factor_ import factorint
from sympy.ntheory.modular import crt
from Crypto.Util.number import long_to_bytes

g=2
n=13407807923699100001122556707991011683559799356310572525877692089795444101264856492920909653436852883666100269727622878890045236257577588884142429726310401
p=115792089210356248762697446949407573530086143415290314195533631308867097853951
c=13039289500598588748147554705701261450867240551995832461020114602848326118576873540325673173824681301010937074023523630350888930788708165464059398310244834

def _discrete_log_pohlig_hellman(n, a, b, factors):
    f = factors
    l = [0] * len(f)
    a %= n
    b %= n
    order = n_order(b, n)

    for i, (pi, ri) in enumerate(f.items()):
        print(f"factor {pi}...")
        for j in range(ri):
            gj = pow(b, l[i], n)
            aj = pow(a * pow(gj, -1, n), order // pi**(j + 1), n)
            bj = pow(b, order // pi, n)
            cj = _discrete_log_trial_mul(n, aj, bj, pi)
            l[i] += cj * pi**j

    f_list = [pi**ri for pi, ri in f.items()]

    # isomorphism for p
    def L(z):
        return (z-1)//p
    _a = L(pow(c,p-1,n))
    _b = L(pow(2,p-1,n))
    x = (_a*pow(_b,-1,p)) % p
    f_list += [p]
    l += [x]

    d, _ = crt(f_list, l)
    return d

factors = {3:1, 5:2, 17:1, 257:1, 641:1, 1531:1, 65537:1, 490463:1, 6700417:1}
flag = _discrete_log_pohlig_hellman(n, c, 2, factors)
print(long_to_bytes(flag))
#so{376f03eec17cf2020cd39e578e9023fb}
```

