---
permalink: /cryptography/rsa/mirror-ecsc
title: mirror - ecsc
---

<br>


Challenge:

<https://hack.cert.pl/challenge/mirror>

```python
import random
import string
from Crypto.Util.number import isPrime, bytes_to_long


def generate_dataset(nbits):
    bits = nbits // 4
    while True:
        A = random.randint(2 ** (bits - 1), 2 ** bits)
        B = random.randint(2 ** (bits - 1), 2 ** bits)
        p = A + (B << bits)
        if isPrime(p):
            q = B + (A << bits)
            if isPrime(q):
                return p, q


def pad(flag, nbits):
    missing = nbits // 8 - len(flag)
    return flag + ''.join(random.choices(string.ascii_letters, k=missing)).encode()


def main():
    print('please wait a while...')
    nbits = 1024
    p, q = generate_dataset(nbits)
    n = p * q
    print(n, nbits)
    flag = bytes_to_long(pad(open("flag.txt", "rb").read(), nbits))
    print(hex(pow(flag, 65537, n)))


main()
```

```
136833849009378541177365407452586723306505444691976749004448551477492393370727121824647697026919571415516837272337651935637064315560075712848623840253845208440409394636665640222581087106974207162724930976023333788275806336989480648037228689764170323692429398688150195468592753198191312296734005651276133646591 1024
0xbb3fc9ea61c02c2b3db67a785fefe3ad16a0188839461351220deb1a2ee00af4cb3ffeb22450c6bc514cc1c9f288d8d58e965ed3eb6224817f3416b742e2ebd310ac3b639479a9f8d4021d81ffc5f63dc4fd9fe238bc3e35469949faece3ae8bf56e79bfca99a27077d2791cb9d207b613608945756e06f671d299829fa8e7e7
```


<br>

<br>

Solve:

You can read of the exact LSB of AB, and approx MSB of AB. 

Brute the rest of the MSB, then you have 2 equations and 2 unknowns to solve A and B. 

```python
n = 136833849009378541177365407452586723306505444691976749004448551477492393370727121824647697026919571415516837272337651935637064315560075712848623840253845208440409394636665640222581087106974207162724930976023333788275806336989480648037228689764170323692429398688150195468592753198191312296734005651276133646591 
c = 0xbb3fc9ea61c02c2b3db67a785fefe3ad16a0188839461351220deb1a2ee00af4cb3ffeb22450c6bc514cc1c9f288d8d58e965ed3eb6224817f3416b742e2ebd310ac3b639479a9f8d4021d81ffc5f63dc4fd9fe238bc3e35469949faece3ae8bf56e79bfca99a27077d2791cb9d207b613608945756e06f671d299829fa8e7e7

AB_lsb = int(f'{n:01024b}'[-256:], 2)
AB_msb_ = int(f'{n:01024b}'[:256], 2)

for AB_msb in range(AB_msb_-1000, AB_msb_): 
    R.<a, b> = ZZ[]
    f = (b * 2^256 + a) * (a * 2^256 + b) - n
    g = a * b - (AB_msb * 2**256 + AB_lsb)
    for A, _ in f.resultant(g, b).univariate_polynomial().roots():
        for B, _ in f.resultant(g, a).univariate_polynomial().roots():
            p = B * 2^256 + A
            q = A * 2^256 + B
            if p*q == n and 1<p<n:
                flag = pow(c, pow(65537, -1, (p-1)*(q-1)), n)
                print(bytes.fromhex(f'{flag:x}'))
```

---


similar chall: 

<https://github.com/AustICCQuals/Challenges2025/tree/main/crypto/teddiursa>
