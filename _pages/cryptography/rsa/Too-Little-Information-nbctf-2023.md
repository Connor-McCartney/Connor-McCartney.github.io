---
permalink: /cryptography/rsa/Too-Little-Information-nbctf-2023
title: Too Little Information - nbctf 2023
---

<br>
<br>

Challenge:

```python
from Crypto.Util.number import *

p = getPrime(512)
q = getPrime(512)

n = p*q
e = 65537

m = bytes_to_long(b"nbctf{[REDACTED]}")

ct = pow(m,e,n)

print(f"{ct = }")
print(f"{e = }")
print(f"{n = }")

hint = (p+q) >> 200 # I can't be giving you that much!
print(f"{hint = }")
```

```
ct = 20030315247290021934293927354887580426070566017560641204155610658927917290198737029903594702064351773446005018155094643288125396810753014936800515440652855824038470725838848349666236623899089094953181436465435270989651491997801177943499187812270081592263331832916362349716591828106306150603120693022149233534
e = 65537
n = 90166344558664675592644684556355545187373291859609367810958775310181360193141550862577281658089332577942193823477148064165061303827534169112815736618901965700400798345371758370344207077280925015891945591352156370597957742921722432314582261224366498475465730899163137511778647694175484386010210005826793007961
hint = 12227137598952006551839416663729660224872609953685427677011433223002140448682395830146750981200
```

<br>

Solve:
<br>
<br>
n = p * (q)
<br>
n = p * (p+q - p)
<br>
0 = p * (p+q - p) - n
<br>
<br>
So using the partial value of (p+q) we can get a partial value of p (MSB same), <br>
then use coppersmith to get the full value of p.

<br>

```python
from Crypto.Util.number import *

ct = 20030315247290021934293927354887580426070566017560641204155610658927917290198737029903594702064351773446005018155094643288125396810753014936800515440652855824038470725838848349666236623899089094953181436465435270989651491997801177943499187812270081592263331832916362349716591828106306150603120693022149233534
e = 65537
n = 90166344558664675592644684556355545187373291859609367810958775310181360193141550862577281658089332577942193823477148064165061303827534169112815736618901965700400798345371758370344207077280925015891945591352156370597957742921722432314582261224366498475465730899163137511778647694175484386010210005826793007961
hint = 12227137598952006551839416663729660224872609953685427677011433223002140448682395830146750981200
 
p_ = var('p_')
approx_p_plus_q = hint << 200
approx_p = int((p_*(approx_p_plus_q - p_) - n).roots()[0][0])

PR.<x> = PolynomialRing(Zmod(n))
f = approx_p + x
x = f.small_roots(X=2**200, beta=0.4)[0]
p = int(f(x))
q = n//p
d = pow(e, -1, (p-1)*(q-1))
print(long_to_bytes(pow(ct, d, n)))
# nbctf{cr34t1v3_fl4gs_4r3_s0_h4rd_t0_m4k3...}
```