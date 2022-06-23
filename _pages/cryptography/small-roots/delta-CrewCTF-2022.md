---
permalink: /cryptography/small-roots/delta-CrewCTF-2022
title: delta - CrewCTF 2022
---

<br>

[Challenge files](https://github.com/Connor-McCartney/CTF_Files/tree/main/2022/CrewCTF/delta)

<br>

```python
delta = getRandomNBitInteger(64)
x = p**2 + 1337*p + delta

val = (pow(2,e,n)*(x**3) + pow(3,e,n)*(x**2) + pow(5,e,n)*x + pow(7,e,n)) % n
```

<br>

small_roots will find x mod p. Note that $$x = p^2 + 1337p + delta$$ so $$x \ (mod \ p) = delta$$. <br>
Delta is a 64 bit integer so our bound should be $$2^{64}$$. We also know p < q, so p < $$sqrt(n)$$.
