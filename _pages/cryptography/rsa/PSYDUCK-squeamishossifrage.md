---
permalink: /cryptography/rsa/PSYDUCK-squeamishossifrage
title: PSYDUCK - squeamishossifrage
---

<br>

[Challenge](https://github.com/zerosumsecurity/squeamishossifrage/tree/main/PSYDUCK)

<br>

```python
from Crypto.PublicKey import RSA

def recover(p_high, n):
        p_bits = (len(bin(n))-2)//2
        p_high_bits = len(bin(p_high)) - 2
        PR.<x> = PolynomialRing(Zmod(n))
        f = p_high * 2**(p_bits-p_high_bits) + x
        x = f.small_roots(X=2**(p_bits-p_high_bits), beta=0.4)
        if x == []:
                return None
        p = int(f(x[0]))
        return p

n = 0xafbbdb7d11bfd71a630151939f122c9fb555e0d0ab7077a551ccaf1846a1be0edea0e5ce467708fe5d14470c98d1cbbd752fbab0816d4f67487fdcdc696376ccb0d10492e74cb6890ffbc69f262f1fd878e5b10bdb9d633e39015d0c96db57e40935046c2c01ff27870d4ef711d5c9c96908e4d4430453bb16a4d9673b61f3ed
e = 0x010001
p_high = 0xf91f28e8b9f28a29da17cf8a4fbc66be473072600bd67646b6372d18b28e1b48b5267e68d77
p = recover(p_high, n)
q = n//p
d = pow(e, -1, (p-1)*(q-1))
key = RSA.construct((int(n),int(e),int(d),int(q),int(p)))

with open("priv.pem", "wb") as f:
    f.write(key.export_key('PEM'))

#openssl smime -decrypt -in flag -inkey priv.pem
```
