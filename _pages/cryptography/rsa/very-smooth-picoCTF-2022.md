---
permalink: /cryptography/rsa/very-smooth-picoCTF-2022
title: Very Smooth - picoCTF 2022
---

The weakness is that p-1 and q-1 are both [smooth numbers](https://en.wikipedia.org/wiki/Smooth_number), so n can be factorised <br>
using [Pollard's p-1 algorithm](https://en.wikipedia.org/wiki/Pollard%27s_p_%E2%88%92_1_algorithm). Once n is factorised we have standard RSA decryption.

```python
from Crypto.Util.number import *
from math import gcd

c = 0x310a423b12a26d0c8244181d158571f973c42e9ebae9ae004aabd371568efaa199e4d163e6698ab3c372d80ceb97eb793ef5183eb931abe57fbdaae2fcf1e195ac16cdf1fe73fcecc35c931edee66f7a7a4c228a8f7edb1fa8902be03e95bf507e5a9ae43e87782da46655ff2a7efd192989e59348d4b520bd6d2485997d0b0f069449b231cd073c89ff792e18b7ca34a6cf6d18ffb7e43d2e0a5eb690f34fd8acb56dc986eb8bf524b311f331f25ecaea4f36cd71bda0f177bcfc27b121a871c126956928dca21528a57af8749b9bb92759dea2d054d434f3fe38178a20e3b1ed75d6afb60e83b15e9193594b4d5ad300bb40754c6886d79ccd0689353a2edd
n = 0x78428327ba89ad5746fd5546b9cab148c9ee3b634eb4b6da6256e56782c6b3fdfddee19cc4a07c1b97c5f5148108f11c29e5ebfbdd8a48247cb64fc39cba6148d2c55ff85762d64e61fdfb57b66c21d2380b4362b5fee96b0553daebec02aa4832c755a3c5e61fb9f18b9504401a1021c7dffbd8896cbf592a2d68692bd15aa141af385b396185ba6582e8e9feacf2f3977a6a8dcdb6835e4807604afea9f1e6063787f6b1bd33f724f11a5834d38f4eebe3019a06adb5011de6e289d18eb020d21d0d97e35be47ff3605bbbb4a6c481a5d01c2383712360a8f3bc63ca63013d3ea2c19dd78eb475d2ff231b4ecccd17b5e81ecdfad9ca4a704c4bf1d53211e9

def pollard_factorisation(N):
        a=2
        n=2
        while 1:
                a = pow(a, n, N)
                res = gcd(a-1,N)
                if res!=1 and res!=N:
                        return res
                n += 1

p = pollard_factorisation(n)
q = n//p
d = pow(65537, -1, (p-1)*(q-1))
m = pow(c, d, n)
print(long_to_bytes(m).decode()) #picoCTF{95d15b05}
```
