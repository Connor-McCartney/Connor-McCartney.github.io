---
permalink: /cryptography/small-roots/random-neobeo
title: Random Challenge from Neobeo
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

```python
s2 = 0x1489ce89f9faffad0bd012837d21a196a146dc371ae54500e9f5fcad433d7ed948ca01a1bdbcee935e62b8b0d9c231ca89a79983778c0ff59babe8ff7b83c922e79910aaef38a442eb9b151aa04ab2233f59c7011b3949986c7d847852a6f1fd71698c48088a2c4cdd17894e385170a219cbc1c93fe343619b67c08c9f03d6c3
```

We have `s2 = (x/y + 420^69)^2 (mod 2^1024+7)`
