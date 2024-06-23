---
permalink: /cryptography/other/WaniCTF2024
title: Wani CTF 2024
---


<br>


# uf

Challenge:

```python
import os
from secrets import randbits
from Crypto.Util.number import bytes_to_long


FLAG = os.environb.get(b"FLAG", b"FAKE{THIS_IS_DUMMY_FLAG}")
m = bytes_to_long(FLAG)
assert m.bit_length() >= 512


def encrypt(m: int, n: int = 512) -> int:
    x = 0
    for i in range(n):
        x <<= 1
        x += m * randbits(1)
        if i >= n // 2:
            x ^= randbits(1)
    return x


X = [encrypt(m) for _ in range(4)]
print(X)
```

```
[6643852762092641655051592752286380661448697120839285262713138738793179330857521051418707355387198243788554658967735136760757552410466512939791351078152197994352930016306075464400264019640466277732596022216246131141036813931972036259910390741311141390889450882074162723823607552591155184799627590418587536982033939537563823, 4495106960532238798978878322218382764459613684889887356979907395021294655849239390809608204284927849117763119933285899077777162943233437728643056322845118660545730870443735090094400144586494098834221418487123653668703665085461676013454922344247818407399456870636622800919629442727075235809213114639237367651539678560390951, 7622226387024225267485603541284038981214490586915816777231024576546652676746968149372915915975325662783469952634025859954515971134032563991925283958708572235632178937041656690377178266198211581176947491463237398083133658483056792368618417698027992083481412961301906342594056438180675328433412539805240307255787971167535638, 1149407465454162408488208063367931363888120160126632926627929705372269921465081968665764846439238807939361247987642326885758277171318666479752274577607727935160689442316433824450832192798328252739495913920016290902086534688608562545166349970831960156036289570935410160077618096614135121287858428753273136461851339553609896]
```

<br>

Solve:

First observe that commenting out 2 lines results in `m == gcd([x0, x1, x2, x3])`:

```python
import os
from secrets import randbits
from Crypto.Util.number import bytes_to_long

FLAG = b'A'*100
m = bytes_to_long(FLAG)
assert m.bit_length() >= 512

def encrypt(m: int, n: int = 512) -> int:
    x = 0
    for i in range(n):
        x <<= 1
        x += m * randbits(1)
        #if i >= n // 2:
        #    x ^= randbits(1)
    return x

x0, x1, x2, x3 = [encrypt(m) for _ in range(4)]
assert m == gcd([x0, x1, x2, x3])
```

<br>

If we uncomment them again then the lsb of each x has been corrupted. 

We can represent this as:

```
x0 = y0*m + z0
x1 = y1*m + z1
x2 = y2*m + z2
x3 = y3*m + z3
```

For small z0, z1, z2, z3.

Next can eliminate m, 

$$\frac{x_0 - z_0}{y_0} = \frac{x_1 - z_1}{y_1} = \frac{x_2 - z_2}{y_2} = \frac{x_3 - z_3}{y_3}$$

Then, 

$$y_1 \cdot (x_0 - z_0) = y_0 \cdot (x_1 - z_1)$$

$$y_1 \cdot x_0 \approx y_0 \cdot x_1$$

$$y_1 \cdot x_0 - y_0 \cdot x_1 = y_1 \cdot z_0 - y_0 \cdot z_1$$

Note that on the LHS we have gotten rid of all the unknown z's, and the value is small compared to the x's, so we can put these in our target vector. 

We can fix x0 and y0 (or another if you like) and repeat with the other equations:

```
y1*x0 - y0*x1 
y2*x0 - y0*x2
y3*x0 - y0*x3
```
