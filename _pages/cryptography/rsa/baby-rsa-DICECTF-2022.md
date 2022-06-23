---
permalink: /cryptography/rsa/baby-rsa-DICECTF-2022
title: baby RSA DICECTF 2022
---

<br>

[Challenge files](https://github.com/Connor-McCartney/CTF_Files/tree/main/2022/DICECTF)

The modulus is 256 bits, fairly small and can be factorised with [cado-nfs](https://gitlab.inria.fr/cado-nfs/cado-nfs).

```
git clone https://gitlab.inria.fr/cado-nfs/cado-nfs
cd cado-nfs
make
time ./cado-nfs.py 57996511214023134147551927572747727074259762800050285360155793732008227782157
```

<br>

This is where I got stuck because gcd(e, phi) is not 1 so there is no private key. Now I am copying from the [author's writeup](https://ctftime.org/writeup/32264). <br>
Using sage's nth_root() function and combining candidates with the chinese remainder theorem will solve broken RSA when e | (p-1) or e | (q-1), or both.

```python
from Crypto.Util.number import long_to_bytes

N = 57996511214023134147551927572747727074259762800050285360155793732008227782157
e = 17
c = 19441066986971115501070184268860318480501957407683654861466353590162062492971
# cado-nfs factorisation
p, q = 172036442175296373253148927105725488217, 337117592532677714973555912658569668821

p_roots = mod(c, p).nth_root(e, all=True)
q_roots = mod(c, q).nth_root(e, all=True)

for pp in p_roots:
    for qq in q_roots:
        flag = long_to_bytes(int(crt([Integer(pp), Integer(qq)], [p,q])))
        if b"dice" in flag:
            print(flag.decode())
```
