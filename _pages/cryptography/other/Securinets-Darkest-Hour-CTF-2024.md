---
permalink: /cryptography/other/Securinets-Darkest-Hour-CTF-2024
title: Securinets Darkest Hour CTF 2024
---

<br>

[Challenge Files](https://github.com/Connor-McCartney/CTF_Files/tree/main/2024/Securinets-Darkest-Hour-CTF)

<br>
<br>


# [FLAG]

<br>

```python
from Crypto.Util.number import *

PR.<flag1, flag2, flag3, flag4> = PolynomialRing(ZZ)
f1 =  flag1+flag2+3*flag3 - 583601198217999802821640273 
f2 =  3*flag1+2*flag2+2*flag3 - 787432535105101541361772353 
f3 =  -flag2-2*flag3+2*flag4 - -119883660368948934388465829 
f4 =  -flag1+flag3-flag4 - -102047525517112400806626497

flag = b""
gb = Ideal([f1, f2, f3, f4]).groebner_basis()
for i in gb:
    flag += long_to_bytes(i.univariate_polynomial().roots()[0][0])
print(flag)

# Securinets{e2b85d839c1cb2937811c7df65117884}
```

<br>

# RSA_sum

<br>

```python
```

<br>

# RSA_over_and_over

<br>

```python
```

<br>

# RSA_ish

<br>

```python
```

<br>

# RSA_Xor

<br>

```python
```

