---
permalink: /cryptography/ecc/Come-on-feel-the-nonce-CTFZone-quals-2023
title: Come on feel the nonce - CTFZone quals 2023
---

<br>

[Challenge files](https://github.com/Connor-McCartney/CTF_Files/tree/main/2023/CTFZone-quals/Come_on_feel_the_nonce)

The attack is outlined in this paper: <https://eprint.iacr.org/2019/023.pdf>
<br>
As well as this accompanying video: <https://www.youtube.com/watch?v=6ssTlSSIJQE>

```python
from hashlib import sha256
from Crypto.Util.number import long_to_bytes
import base64

def basis():
    t1 = r1 * pow(s1, -1, q)
    t2 = r2 * pow(s2, -1, q)
    t3 = r3 * pow(s3, -1, q)
    a1 = h1 * pow(s1, -1, q)
    a2 = h2 * pow(s2, -1, q)
    a3 = h3 * pow(s3, -1, q)
    basis = [ [q,    0,    0,     0,     0],
              [0,    q,    0,     0,     0],
              [0,    0,    q,     0,     0],
              [t1,   t2,   t3,    B/q,   0],
              [a1,   a2,   a3,    0,     B]]
    return Matrix(QQ, basis)

def attack():
    M = basis()
    k = M.LLL()[1][0]
    d = (s1*Mod(k, q) - h1) * pow(r1, -1, q)
    return d

def decrypt(enc, priv):
    res = bytearray()
    data = base64.b64decode(enc.encode())
    st = sha256(long_to_bytes(int(priv))).digest()
    for i, b in enumerate(data):
        res.append(b^^st[i])
    return res.decode()


h1 = 106132995759974998927623038931468101728092864039673367661724550078579493516352
r1 = 18051166252496627800102264022724027258301377836259456556817994423615643066667
s1 = 92640317177062616510163453417907524626349777891295335142117609371090060820235
h2 = 7879316208808238663812485364896527134152960535409744690121857898575626153029
r2 = 115471704120523893976825820273729861954380716558612823937677135779401972000099
s2 = 88253444681758261894850337672595478098707689792795126664973754773335910861625
h3 = 108514392945691456671012287741933342528603208652973703270072343215378534310088
r3 = 17273357182041772804140680226822003503928964298970616439008405277082716423350
s3 = 65509764364537601259350672638899752182831914240350569385339863955089362099960

q = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
B = 2**64
enc = "hOtHc2dafgWuv2nHQDGsoGoF+BmDhy3N0seYgY9kVnw="
d = attack()
print(decrypt(enc, d))
```
