---
permalink: /cryptography/small-roots/xy
title: xy
---

<br>


Challenge:

```python
# can you recover my secret if I tell you its square?
secret = mod(randrange(2^200), 2^1024+7)/randrange(2^200) + 420^69 # this is sage, obviously
print(hex(secret^2))
# 0x1489ce89f9faffad0bd012837d21a196a146dc371ae54500e9f5fcad433d7ed948ca01a1bdbcee935e62b8b0d9c231ca89a79983778c0ff59babe8ff7b83c922e79910aaef38a442eb9b151aa04ab2233f59c7011b3949986c7d847852a6f1fd71698c48088a2c4cdd17894e385170a219cbc1c93fe343619b67c08c9f03d6c3
```


<br>


Solve:

There is no flag, the goal is just to recover the 2 random unknowns x and y. 


We have `s2 = (x/y + 420^69)^2 (mod 2^1024+7)`

The modulus is too big to be factored so we can't just take a modular square root. 

Basically the trick is like bivariate coppersmith, but 

using polynomial gcd instead of something like jacobian-newton or groebner for the root solving!

```python
load('https://raw.githubusercontent.com/Connor-McCartney/coppersmith/main/coppersmith.sage')
s2 = 0x1489ce89f9faffad0bd012837d21a196a146dc371ae54500e9f5fcad433d7ed948ca01a1bdbcee935e62b8b0d9c231ca89a79983778c0ff59babe8ff7b83c922e79910aaef38a442eb9b151aa04ab2233f59c7011b3949986c7d847852a6f1fd71698c48088a2c4cdd17894e385170a219cbc1c93fe343619b67c08c9f03d6c3
PR.<x, y> = PolynomialRing(Zmod(2^1024+7), 2)
f = x^2 + y^2*(420^69)^2 + 2*420^69*x*y - s2*y^2
H = multivariate_shift_polynomials(f, bounds=(2^200, 2^200), m=2, d=1)
print(gcd(H[1][1], H[1][0])) # polygcd
```

<br>

```
214839072752248251123651515446256920355111471128718925321875*x - 772665869227543933401727241572361134900046583146442535761594*y
```

We get this, and of course the positive roots are:

```python
x = 772665869227543933401727241572361134900046583146442535761594
y = 214839072752248251123651515446256920355111471128718925321875
```
